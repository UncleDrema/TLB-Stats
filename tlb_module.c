#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/perf_event.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#define MAX_PROCESSES 10

static struct perf_event *tlb_events[MAX_PROCESSES];
static struct perf_event_attr tlb_event_attr;
static struct timer_list read_timer;

static void dtlb_miss_handler(struct perf_event *event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    // Обработчик пуст, так как мы читаем счетчики напрямую
}

static void read_counter(struct timer_list *t)
{
    struct task_struct *task;
    int i = 0;

    for_each_process(task) {
        if (i >= MAX_PROCESSES)
            break;

        if (tlb_events[i]) {
            u64 count = perf_event_read_value(tlb_events[i], NULL, NULL);
            printk(KERN_INFO "+[TLB] Process: %s (PID: %d), DTLB misses: %llu\n", task->comm, task->pid, count);
        }
        i++;
    }

    // Перезапуск таймера
    mod_timer(&read_timer, jiffies + 5 * HZ);
}

static int __init dtlb_miss_stats_init(void) {
    struct task_struct *task;
    int i = 0;

    printk(KERN_INFO "+[TLB] module loading...\n");

    memset(&tlb_event_attr, 0, sizeof(tlb_event_attr));
    tlb_event_attr.type = PERF_TYPE_HW_CACHE;
    tlb_event_attr.size = sizeof(struct perf_event_attr);
    tlb_event_attr.config = (PERF_COUNT_HW_CACHE_DTLB
        | (PERF_COUNT_HW_CACHE_OP_READ << 8)
        | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16));

    for_each_process(task) {
        if (i >= MAX_PROCESSES)
            break;

        tlb_events[i] = perf_event_create_kernel_counter(&tlb_event_attr,
                                                         -1,
                                                         task,
                                                         dtlb_miss_handler,
                                                         NULL);

        if (IS_ERR(tlb_events[i])) {
            printk(KERN_ERR "+[TLB] Failed to create perf event for process %s (PID: %d): %ld\n", task->comm, task->pid, PTR_ERR(tlb_events[i]));
            tlb_events[i] = NULL;
        }
        i++;
    }

    printk(KERN_INFO "+[TLB] module loaded.\n");

    // Запуск таймера для чтения счетчиков через 5 секунд
    timer_setup(&read_timer, read_counter, 0);
    mod_timer(&read_timer, jiffies + 5 * HZ);

    return 0;
}

static void __exit dtlb_miss_stats_exit(void) {
    int i;

    printk(KERN_INFO "+[TLB] module unloading...\n");

    for (i = 0; i < MAX_PROCESSES; i++) {
        if (tlb_events[i])
            perf_event_release_kernel(tlb_events[i]);
    }

    del_timer(&read_timer);
}

module_init(dtlb_miss_stats_init);
module_exit(dtlb_miss_stats_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UncleDrema");
MODULE_DESCRIPTION("Kernel module to collect DTLB misses for processes.");
