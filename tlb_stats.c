#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/perf_event.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/seq_file.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UncleDrema");
MODULE_DESCRIPTION("Kernel module to collect DTLB misses for processes.");

static struct work_struct update_statistics_work;
static struct perf_event_attr dtlb_read_pea;
static struct perf_event_attr dtlb_write_pea;
static struct timer_list read_timer;
static struct proc_dir_entry *tlbmiss_dir;

/* Each finalized 1-second interval. */
struct dtlb_interval {
    u64 dtlb_read_misses;
    u64 dtlb_write_misses;
    u64 enabled;
    u64 running;
    struct list_head list;
};

/* Holds per-process tracking data. */
struct dtlb_proc_info {
    struct task_struct *task;
    struct perf_event *dtlb_read_ev;
    struct perf_event *dtlb_write_ev;

    struct list_head interval_list;
    struct list_head list;

    struct proc_dir_entry *proc_file;
    char proc_entry_name[16];
    char comm[TASK_COMM_LEN];
};

static LIST_HEAD(dtlb_process_list);
static struct kmem_cache *dtlb_proc_cache;
static struct kmem_cache *dtlb_interval_cache;

/* Unused, but function prototype required by perf_event_create_kernel_counter. */
static void dtlb_miss_handler(struct perf_event *dtlb_read_ev,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{ }

static struct dtlb_proc_info* find_process_info(struct task_struct *task)
{
    struct dtlb_proc_info *info;
    list_for_each_entry(info, &dtlb_process_list, list) {
        if (info->task == task)
            return info;
    }
    return NULL;
}

/* Show aggregated statistics for each process. */
static int dtlb_proc_show(struct seq_file *m, void *v)
{
    struct dtlb_proc_info *info = m->private;
    struct dtlb_interval *intrv;
    u64 total_dtlb_read_misses = 0, total_dtlb_write_misses = 0,
        max_dtlb_read_misses = 0, max_dtlb_write_misses = 0,
        total_enabled, total_running, min_enabled = ULLONG_MAX, min_running = ULLONG_MAX, max_enabled = 0, max_running = 0;
    size_t count_intervals = 0,
           count_dtlb_read_nonzero = 0, count_dtlb_write_nonzero = 0;

    u64 dtlb_read_prev, dtlb_write_prev, enabled_prev, running_prev;
    u64 dtlb_read_diff, dtlb_write_diff, enabled_diff, running_diff;
    
    list_for_each_entry(intrv, &info->interval_list, list) {
        if (count_intervals == 0)
        {
            dtlb_read_prev = intrv->dtlb_read_misses;
            dtlb_write_prev = intrv->dtlb_write_misses;
            enabled_prev = intrv->enabled;
            running_prev = intrv->running;

            dtlb_read_diff = dtlb_read_prev;
            dtlb_write_diff = dtlb_write_prev;
            enabled_diff = enabled_prev;
            running_diff = running_prev;
            
        }
        else
        {
            dtlb_read_diff = intrv->dtlb_read_misses - dtlb_read_prev;
            dtlb_write_diff = intrv->dtlb_write_misses - dtlb_write_prev;
            enabled_diff = intrv->enabled - enabled_prev;
            running_diff = intrv->running - running_prev;

            dtlb_read_prev = intrv->dtlb_read_misses;
            dtlb_write_prev = intrv->dtlb_write_misses;
            enabled_prev = intrv->enabled;
            running_prev = intrv->running;
        }

        count_intervals++;

        total_enabled += enabled_diff;
        total_running += running_diff;

        if (enabled_diff < min_enabled)
            min_enabled = enabled_diff;
        if (enabled_diff > max_enabled)
            max_enabled = enabled_diff;

        if (running_prev < min_running)
            min_running = running_prev;
        if (running_prev > max_running)
            max_running = running_prev;

        if (dtlb_read_diff > 0) {
            total_dtlb_read_misses += dtlb_read_diff;
            count_dtlb_read_nonzero++;
            if (dtlb_read_diff > max_dtlb_read_misses)
                max_dtlb_read_misses = dtlb_read_diff;
        }

        if (dtlb_write_diff > 0) {
            total_dtlb_write_misses += dtlb_write_diff;
            count_dtlb_write_nonzero++;
            if (dtlb_write_diff > max_dtlb_write_misses)
                max_dtlb_write_misses = dtlb_write_diff;
        }
    }

    seq_printf(m, "Process: %s (PID %d)\n", info->comm, task_pid_nr(info->task));
    seq_printf(m, "Intervals recorded: %zu\n", count_intervals);

    if (count_intervals == 0) {
        seq_printf(m, "No intervals recorded.\n");
        return 0;
    }

    seq_printf(m, "DTLB read misses: %llu\n", (unsigned long long)total_dtlb_read_misses);
    seq_printf(m, "DTLB write misses: %llu\n", (unsigned long long)total_dtlb_write_misses);

    seq_printf(m, "avg(DTLB read) = %llu misses/sec\n",
               (unsigned long long)(total_dtlb_read_misses / count_intervals));
    seq_printf(m, "avg(DTLB write) = %llu misses/sec\n",
                (unsigned long long)(total_dtlb_write_misses / count_intervals));

    if (count_dtlb_read_nonzero > 0) {
        u64 avg_dtlb_read_nonzero = total_dtlb_read_misses / count_dtlb_read_nonzero;
        seq_printf(m, "avg(DTLB read-0) = %llu misses/sec (intervals with misses)\n",
                   (unsigned long long)avg_dtlb_read_nonzero);
    } else {
        seq_printf(m, "avg(DTLB read-0) = 0 (no intervals with misses)\n");
    }

    if (count_dtlb_write_nonzero > 0) {
        u64 avg_dtlb_write_nonzero = total_dtlb_write_misses / count_dtlb_write_nonzero;
        seq_printf(m, "avg(DTLB write-0) = %llu misses/sec (intervals with misses)\n",
                   (unsigned long long)avg_dtlb_write_nonzero);
    } else {
        seq_printf(m, "avg(DTLB write-0) = 0 (no intervals with misses)\n");
    }

    seq_printf(m, "peak(DTLB read)  = %llu misses in a single interval\n",
               (unsigned long long)max_dtlb_read_misses);
    seq_printf(m, "peak(DTLB write)  = %llu misses in a single interval\n",
                (unsigned long long)max_dtlb_write_misses);

    seq_printf(m, "avg_enabled  = %llu\n", (unsigned long long)(total_enabled / count_intervals));
    seq_printf(m, "avg_running  = %llu\n", (unsigned long long)(total_running / count_intervals));
    seq_printf(m, "min_enabled  = %llu\n", (unsigned long long)min_enabled);
    seq_printf(m, "min_running  = %llu\n", (unsigned long long)min_running);
    seq_printf(m, "max_enabled  = %llu\n", (unsigned long long)max_enabled);
    seq_printf(m, "max_running  = %llu\n", (unsigned long long)max_running);
    
    return 0;
}

static int dtlb_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, dtlb_proc_show, pde_data(inode));
}

/* Use struct proc_ops to handle /proc/tlbmiss/<PID>. */
static const struct proc_ops dtlb_proc_ops = {
    .proc_open    = dtlb_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static void remove_process_info(struct dtlb_proc_info *info)
{
    struct dtlb_interval *intrv, *tmp;
    list_del(&info->list);

    if (info->dtlb_read_ev)
        perf_event_release_kernel(info->dtlb_read_ev);
    if (info->dtlb_write_ev)
        perf_event_release_kernel(info->dtlb_write_ev);

    if (info->proc_file) {
        remove_proc_entry(info->proc_entry_name, tlbmiss_dir);
        info->proc_file = NULL;
    }

    list_for_each_entry_safe(intrv, tmp, &info->interval_list, list) {
        list_del(&intrv->list);
        kmem_cache_free(dtlb_interval_cache, intrv);
    }
    kmem_cache_free(dtlb_proc_cache, info);
}

/* Create and add a new dtlb_proc_info for a given task. */
static struct dtlb_proc_info* create_process_info(struct task_struct *task)
{
    struct dtlb_proc_info *info;
    struct perf_event *dtlb_read_ev, *dtlb_write_ev;
    char name[16];

    dtlb_read_ev = perf_event_create_kernel_counter(&dtlb_read_pea, -1, task,
                                           dtlb_miss_handler, NULL);
    if (IS_ERR(dtlb_read_ev))
    {
        printk(KERN_ERR "[TLB] Failed to create perf_event for DTLB read misses: %ld\n", PTR_ERR(dtlb_read_ev));
        return NULL;
    }

    
    dtlb_write_ev = perf_event_create_kernel_counter(&dtlb_write_pea, -1, task,
                                           dtlb_miss_handler, NULL);
    if (IS_ERR(dtlb_write_ev))
    {
        printk(KERN_ERR "[TLB] Failed to create perf_event for DTLB write misses: %ld\n", PTR_ERR(dtlb_write_ev));
        perf_event_release_kernel(dtlb_read_ev);
        return NULL;
    }

    info = kmem_cache_alloc(dtlb_proc_cache, GFP_KERNEL);
    if (!info) {
        perf_event_release_kernel(dtlb_read_ev);
        perf_event_release_kernel(dtlb_write_ev);
        return NULL;
    }
    
    info->task = task;
    info->dtlb_read_ev = dtlb_read_ev;
    INIT_LIST_HEAD(&info->interval_list);
    get_task_comm(info->comm, task);

    snprintf(name, sizeof(name), "%d", task_pid_nr(task));
    strscpy(info->proc_entry_name, name, sizeof(info->proc_entry_name));

    info->proc_file = proc_create_data(info->proc_entry_name,
                                       0444,
                                       tlbmiss_dir,
                                       &dtlb_proc_ops,
                                       info);
    if (!info->proc_file) {
        kmem_cache_free(dtlb_proc_cache, info);
        perf_event_release_kernel(dtlb_read_ev);
        perf_event_release_kernel(dtlb_write_ev);
        return NULL;
    }
    return info;
}

static void track_new_processes(void)
{
    struct task_struct *task;
    for_each_process(task) {
        if (!find_process_info(task)) {
            struct dtlb_proc_info *info = create_process_info(task);
            if (info)
                list_add_tail(&info->list, &dtlb_process_list);
        }
    }
}

static void remove_finished_processes(void)
{
    struct dtlb_proc_info *info, *tmp;
    list_for_each_entry_safe(info, tmp, &dtlb_process_list, list) {
        if (!pid_alive(info->task))
            remove_process_info(info);
    }
}

static void add_interval(struct dtlb_proc_info *info,
                         u64 dtlb_read_misses, u64 dtlb_write_misses,
                         u64 itlb_read_misses, u64 itlb_write_misses,
                         u64 enabled, u64 running)
{
    if (!info)
        return;

    struct dtlb_interval *interval;

    interval = kmem_cache_alloc(dtlb_interval_cache, GFP_KERNEL);
    if (!interval)
        return;

    interval->dtlb_read_misses = dtlb_read_misses;
    interval->dtlb_write_misses = dtlb_write_misses;
    interval->enabled = enabled;
    interval->running = running;

    list_add_tail(&interval->list, &info->interval_list);
}

static void update_process_intervals(void)
{
    struct dtlb_proc_info *info;
    u64 enabled, running, dtlb_read_misses, dtlb_write_misses, itlb_read_misses, itlb_write_misses;
    list_for_each_entry(info, &dtlb_process_list, list) {
        if (!info->dtlb_read_ev)
            continue;

        dtlb_read_misses = info->dtlb_read_ev ? perf_event_read_value(info->dtlb_read_ev, &enabled, &running) : 0;
        dtlb_write_misses = info->dtlb_write_ev ? perf_event_read_value(info->dtlb_write_ev, &enabled, &running) : 0;

        add_interval(info, dtlb_read_misses, dtlb_write_misses, itlb_read_misses, itlb_write_misses, enabled, running);
    }
}

static void update_statistics_work_handler(struct work_struct *work)
{
    remove_finished_processes();
    track_new_processes();
    update_process_intervals();

    {
        int count = 0;
        struct dtlb_proc_info *info;
        list_for_each_entry(info, &dtlb_process_list, list)
            count++;
        printk(KERN_INFO "[TLB] Currently tracked: %d processes\n", count);
    }

    mod_timer(&read_timer, jiffies + HZ);
}

static void update_statistics(struct timer_list *t)
{
    schedule_work(&update_statistics_work);
    mod_timer(&read_timer, jiffies + HZ);
}

static void dtlb_proc_info_ctr(void *data)
{
    memset(data, 0, sizeof(struct dtlb_proc_info));
}

static void dtlb_interval_ctr(void *data)
{
    memset(data, 0, sizeof(struct dtlb_interval));
}

static int __init dtlb_miss_stats_init(void)
{
    struct dtlb_proc_info *info;
    struct task_struct *task;

    printk(KERN_INFO "[TLB] module loading...\n");

    memset(&dtlb_read_pea, 0, sizeof(dtlb_read_pea));
    dtlb_read_pea.type = PERF_TYPE_HW_CACHE;
    dtlb_read_pea.size = sizeof(struct perf_event_attr);
    dtlb_read_pea.config = (PERF_COUNT_HW_CACHE_DTLB
                            | (PERF_COUNT_HW_CACHE_OP_READ << 8)
                            | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));

    memset(&dtlb_write_pea, 0, sizeof(dtlb_write_pea));
    dtlb_write_pea.type = PERF_TYPE_HW_CACHE;
    dtlb_write_pea.size = sizeof(struct perf_event_attr);
    dtlb_write_pea.config = (PERF_COUNT_HW_CACHE_DTLB
                             | (PERF_COUNT_HW_CACHE_OP_WRITE << 8)
                             | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));

    dtlb_proc_cache = kmem_cache_create("dtlb_proc_info",
                                        sizeof(struct dtlb_proc_info),
                                        0, SLAB_HWCACHE_ALIGN, dtlb_proc_info_ctr);
    if (!dtlb_proc_cache) {
        printk(KERN_ERR "[TLB] Failed to create dtlb_proc_info cache\n");
        return -ENOMEM;
    }

    dtlb_interval_cache = kmem_cache_create("dtlb_interval",
                                           sizeof(struct dtlb_interval),
                                           0, SLAB_HWCACHE_ALIGN, dtlb_interval_ctr);
    if (!dtlb_interval_cache) {
        kmem_cache_destroy(dtlb_proc_cache);
        printk(KERN_ERR "[TLB] Failed to create dtlb_interval cache\n");
        return -ENOMEM;
    }

    tlbmiss_dir = proc_mkdir("tlbmiss", NULL);
    if (!tlbmiss_dir) {
        kmem_cache_destroy(dtlb_interval_cache);
        kmem_cache_destroy(dtlb_proc_cache);
        printk(KERN_ERR "[TLB] Failed to create /proc/tlbmiss\n");
        return -ENOMEM;
    }

    for_each_process(task) {
        info = create_process_info(task);
        if (info)
            list_add_tail(&info->list, &dtlb_process_list);
    }

    INIT_WORK(&update_statistics_work, update_statistics_work_handler);

    timer_setup(&read_timer, update_statistics, 0);
    mod_timer(&read_timer, jiffies + HZ);

    printk(KERN_INFO "[TLB] module loaded.\n");
    return 0;
}

static void __exit dtlb_miss_stats_exit(void)
{
    struct dtlb_proc_info *info, *tmp;

    printk(KERN_INFO "[TLB] module unloading...\n");

    del_timer_sync(&read_timer);

    list_for_each_entry_safe(info, tmp, &dtlb_process_list, list) {
        remove_process_info(info);
    }

    remove_proc_entry("tlbmiss", NULL);

    if (dtlb_interval_cache)
        kmem_cache_destroy(dtlb_interval_cache);
    if (dtlb_proc_cache)
        kmem_cache_destroy(dtlb_proc_cache);

    printk(KERN_INFO "[TLB] module unloaded.\n");
}

module_init(dtlb_miss_stats_init);
module_exit(dtlb_miss_stats_exit);