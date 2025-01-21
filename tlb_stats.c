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
#include <linux/string.h> // for strscpy/scnprintf

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UncleDrema");
MODULE_DESCRIPTION("Kernel module to collect DTLB misses for processes.");

static struct perf_event_attr tlb_event_attr;
static struct timer_list read_timer;
static struct proc_dir_entry *tlbmiss_dir;

/* Each finalized 1-second interval. */
struct dtlb_interval {
    ktime_t start_time;
    ktime_t end_time;
    /* Computed deltas for this interval */
    u64 dtlb_misses;
    u64 enabled_delta;
    u64 running_delta;
    /* Raw values used for finalizing the interval */
    u64 raw_count;
    u64 raw_enabled;
    u64 raw_running;
    struct list_head list;
};

/* Holds per-process tracking data. */
struct dtlb_proc_info {
    struct task_struct *task;
    struct perf_event *event;

    /* The "active" interval being built. */
    struct dtlb_interval *current_interval;

    /* All completed intervals. */
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
static void dtlb_miss_handler(struct perf_event *event,
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
    u64 total_misses = 0, total_misses_nonzero = 0;
    u64 max_misses = 0;
    u64 total_enabled = 0, total_running = 0;
    size_t count_intervals = 0, count_nonzero = 0;

    list_for_each_entry(intrv, &info->interval_list, list) {
        count_intervals++;
        total_misses += intrv->dtlb_misses;
        total_enabled += intrv->enabled_delta;
        total_running += intrv->running_delta;

        if (intrv->dtlb_misses > 0) {
            count_nonzero++;
            total_misses_nonzero += intrv->dtlb_misses;
        }
        if (intrv->dtlb_misses > max_misses)
            max_misses = intrv->dtlb_misses;
    }

    seq_printf(m, "Process: %s (PID %d)\n", info->comm, task_pid_nr(info->task));
    seq_printf(m, "Intervals recorded: %zu\n", count_intervals);

    if (count_intervals > 0) {
        u64 avg_all = total_misses / count_intervals;
        seq_printf(m, "avg()   = %llu misses/sec (all intervals)\n",
                   (unsigned long long)avg_all);
    } else {
        seq_printf(m, "avg()   = 0 (no intervals)\n");
    }

    if (count_nonzero > 0) {
        u64 avg_nonzero = total_misses_nonzero / count_nonzero;
        seq_printf(m, "avg(-0) = %llu misses/sec (intervals with misses)\n",
                   (unsigned long long)avg_nonzero);
    } else {
        seq_printf(m, "avg(-0) = 0 (no intervals with misses)\n");
    }

    seq_printf(m, "peak()  = %llu misses in a single interval\n",
               (unsigned long long)max_misses);

    if (count_intervals > 0) {
        u64 avg_en = total_enabled / count_intervals;
        u64 avg_run = total_running / count_intervals;
        seq_printf(m, "avg_enabled  = %llu\n", (unsigned long long)avg_en);
        seq_printf(m, "avg_running  = %llu\n", (unsigned long long)avg_run);
    }
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

    if (info->event)
        perf_event_release_kernel(info->event);

    if (info->proc_file) {
        remove_proc_entry(info->proc_entry_name, tlbmiss_dir);
        info->proc_file = NULL;
    }

    if (info->current_interval) {
        kmem_cache_free(dtlb_interval_cache, info->current_interval);
        info->current_interval = NULL;
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
    struct perf_event *evt;
    char name[16];

    evt = perf_event_create_kernel_counter(&tlb_event_attr, -1, task,
                                           dtlb_miss_handler, NULL);
    if (IS_ERR(evt))
        return NULL;

    info = kmem_cache_alloc(dtlb_proc_cache, GFP_KERNEL);
    if (!info) {
        perf_event_release_kernel(evt);
        return NULL;
    }
    memset(info, 0, sizeof(*info));
    info->task = task;
    info->event = evt;
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
        perf_event_release_kernel(evt);
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

/* Creates a new interval structure to hold raw counters. */
static void start_new_interval(struct dtlb_proc_info *info,
                               u64 raw_count, u64 raw_enabled, u64 raw_running)
{
    struct dtlb_interval *intrv;

    intrv = kmem_cache_alloc(dtlb_interval_cache, GFP_KERNEL);
    if (!intrv)
        return;

    memset(intrv, 0, sizeof(*intrv));
    intrv->start_time  = ktime_get();
    intrv->raw_count   = raw_count;
    intrv->raw_enabled = raw_enabled;
    intrv->raw_running = raw_running;

    info->current_interval = intrv;
}

/* Finalizes the current interval with new raw data, then links it into the list. */
static void finalize_interval(struct dtlb_proc_info *info,
                              u64 raw_count, u64 raw_enabled, u64 raw_running)
{
    struct dtlb_interval *intrv = info->current_interval;

    intrv->dtlb_misses   = raw_count   - intrv->raw_count;
    intrv->enabled_delta = raw_enabled - intrv->raw_enabled;
    intrv->running_delta = raw_running - intrv->raw_running;
    intrv->end_time      = ktime_get();

    list_add_tail(&intrv->list, &info->interval_list);
    info->current_interval = NULL;
}

static void update_process_intervals(void)
{
    struct dtlb_proc_info *info;
    list_for_each_entry(info, &dtlb_process_list, list) {
        if (!info->event)
            continue;

        u64 enabled_raw = 0, running_raw = 0;
        u64 current_count = perf_event_read_value(info->event,
                                                  &enabled_raw,
                                                  &running_raw);

        /* If we have an active interval, finalize it. */
        if (info->current_interval) {
            finalize_interval(info, current_count, enabled_raw, running_raw);
        }

        /* Start a new interval baseline for the next read. */
        start_new_interval(info, current_count, enabled_raw, running_raw);
    }
}

static void read_counter(struct timer_list *t)
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

static int __init dtlb_miss_stats_init(void)
{
    struct dtlb_proc_info *info;
    struct task_struct *task;

    printk(KERN_INFO "[TLB] module loading...\n");

    memset(&tlb_event_attr, 0, sizeof(tlb_event_attr));
    tlb_event_attr.type = PERF_TYPE_HW_CACHE;
    tlb_event_attr.size = sizeof(struct perf_event_attr);
    tlb_event_attr.config = (PERF_COUNT_HW_CACHE_DTLB
                            | (PERF_COUNT_HW_CACHE_OP_READ << 8)
                            | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));

    dtlb_proc_cache = kmem_cache_create("dtlb_proc_info",
                                        sizeof(struct dtlb_proc_info),
                                        0, SLAB_HWCACHE_ALIGN, NULL);
    if (!dtlb_proc_cache) {
        printk(KERN_ERR "[TLB] Failed to create dtlb_proc_info cache\n");
        return -ENOMEM;
    }

    dtlb_interval_cache = kmem_cache_create("dtlb_interval",
                                           sizeof(struct dtlb_interval),
                                           0, SLAB_HWCACHE_ALIGN, NULL);
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

    timer_setup(&read_timer, read_counter, 0);
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