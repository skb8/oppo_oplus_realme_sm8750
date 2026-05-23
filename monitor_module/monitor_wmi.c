// SPDX-License-Identifier: GPL-2.0
/*
 * monitor_wmi.c — стандартный kernel module (.ko)
 *
 * Включает Wi-Fi monitor mode на OnePlus 13 (WCN7850/peach)
 * путём инъекции кастомной WMI команды в qca_cld3_peach_v2.
 *
 * Метод:
 *   kprobe на wmi_unified_cmd_send_over_qmi →
 *   захватываем wmi_handle при первом вызове →
 *   отправляем команду 0x49 / subcmd 0x42 в firmware
 *
 * Управление:
 *   echo 1 > /proc/monitor_wmi   — включить monitor mode
 *   echo 0 > /proc/monitor_wmi   — выключить
 *   cat   /proc/monitor_wmi      — статус
 *
 * Сборка:
 *   Нужны заголовки ядра 6.6.127-palaziks-ShiftPorts
 *   make -C <kernel_headers> M=$(pwd) modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("custom");
MODULE_DESCRIPTION("Wi-Fi monitor mode enabler for WCN7850/peach via WMI cmd 0x49");
MODULE_VERSION("1.0");

/* ─── WMI типы ──────────────────────────────────────────────────────────── */

typedef void    *wmi_unified_t;
typedef void    *wmi_buf_t;

typedef wmi_buf_t (*fn_wmi_buf_alloc_t)(wmi_unified_t wmi,
					uint16_t len,
					const char *func,
					uint32_t line);
typedef void      (*fn_wmi_buf_free_t)(wmi_buf_t buf);
typedef int       (*fn_wmi_cmd_send_t)(wmi_unified_t wmi,
				       wmi_buf_t buf,
				       uint32_t buflen,
				       uint32_t cmd_id);

/* ─── Payload нашей команды ─────────────────────────────────────────────── */
/*
 * Firmware patch принимает:
 *   WMI cmd_id = 0x49  (rx_unit_test dispatch)
 *   payload[0] = 0x42  (наш subcmd)
 *   payload[1] = 0/1   (выкл/вкл monitor mode)
 */
#define MONITOR_CMD_ID   0x49u
#define MONITOR_SUBCMD   0x42u

struct monitor_payload {
	uint32_t subcmd;
	uint32_t enable;
};

/* ─── Глобальное состояние ──────────────────────────────────────────────── */

static DEFINE_MUTEX(g_lock);

static wmi_unified_t       g_wmi_handle  = NULL;
static fn_wmi_buf_alloc_t  g_buf_alloc   = NULL;
static fn_wmi_buf_free_t   g_buf_free    = NULL;
static fn_wmi_cmd_send_t   g_cmd_send    = NULL;

static bool g_handle_captured = false;
static int  g_current_mode    = -1;  /* -1=неизвестно, 0=выкл, 1=вкл */
static int  g_pending_enable  = -1;

/* ─── Отправка WMI команды ──────────────────────────────────────────────── */

static int do_send_monitor_cmd(int enable)
{
	wmi_buf_t buf;
	struct monitor_payload *p;
	int ret;

	if (!g_wmi_handle || !g_buf_alloc || !g_buf_free || !g_cmd_send) {
		pr_err("[monitor_wmi] WMI функции недоступны\n");
		return -ENODEV;
	}

	buf = g_buf_alloc(g_wmi_handle,
			  sizeof(struct monitor_payload),
			  __func__, __LINE__);
	if (!buf) {
		pr_err("[monitor_wmi] wmi_buf_alloc вернул NULL\n");
		return -ENOMEM;
	}

	p = (struct monitor_payload *)buf;
	p->subcmd = MONITOR_SUBCMD;
	p->enable = (uint32_t)enable;

	pr_info("[monitor_wmi] → WMI cmd=0x%x subcmd=0x%x enable=%d\n",
		MONITOR_CMD_ID, MONITOR_SUBCMD, enable);

	ret = g_cmd_send(g_wmi_handle,
			 buf,
			 sizeof(struct monitor_payload),
			 MONITOR_CMD_ID);
	if (ret != 0) {
		pr_err("[monitor_wmi] wmi_cmd_send вернул %d\n", ret);
		g_buf_free(buf);
	} else {
		pr_info("[monitor_wmi] WMI команда отправлена ✓\n");
		g_current_mode = enable;
	}

	return ret;
}

/* ─── kprobe на wmi_unified_cmd_send_over_qmi ───────────────────────────── */
/*
 * Срабатывает при каждом вызове функции.
 * При первом вызове сохраняем wmi_handle из первого аргумента (x0 на arm64).
 */

static struct kprobe g_kp = {
	.symbol_name = "wmi_unified_cmd_send_over_qmi",
};

static int kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * На arm64 аргументы:
	 *   regs->regs[0] = wmi_handle (первый аргумент)
	 *   regs->regs[1] = buf
	 *   regs->regs[2] = buflen
	 *   regs->regs[3] = cmd_id
	 */
	wmi_unified_t handle = (wmi_unified_t)regs->regs[0];

	mutex_lock(&g_lock);

	if (!g_handle_captured && handle) {
		g_wmi_handle = handle;
		g_handle_captured = true;
		pr_info("[monitor_wmi] wmi_handle захвачен: %px\n", handle);

		/* Снимаем kprobe — handle получен */
		disable_kprobe(&g_kp);

		/* Отправляем ожидающую команду */
		if (g_pending_enable >= 0) {
			int en = g_pending_enable;
			g_pending_enable = -1;
			mutex_unlock(&g_lock);
			do_send_monitor_cmd(en);
			return 0;
		}
	}

	mutex_unlock(&g_lock);
	return 0;
}

/* ─── Work для асинхронной отправки команды ────────────────────────────── */

static struct work_struct g_work;
static int g_work_val = -1;

static void send_work_fn(struct work_struct *w)
{
	int val;

	mutex_lock(&g_lock);
	val = g_work_val;
	g_work_val = -1;

	if (val < 0) {
		mutex_unlock(&g_lock);
		return;
	}

	if (!g_handle_captured) {
		/* handle ещё не захвачен — включаем kprobe и ждём */
		g_pending_enable = val;
		mutex_unlock(&g_lock);
		enable_kprobe(&g_kp);
		pr_info("[monitor_wmi] kprobe активирован, ждём первого WMI вызова...\n");
	} else {
		mutex_unlock(&g_lock);
		do_send_monitor_cmd(val);
	}
}

/* ─── /proc/monitor_wmi ─────────────────────────────────────────────────── */

static ssize_t proc_write(struct file *f, const char __user *buf,
			  size_t count, loff_t *pos)
{
	char kbuf[4] = {0};
	int val;

	if (count > 3)
		count = 3;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	if (kbuf[0] == '1')
		val = 1;
	else if (kbuf[0] == '0')
		val = 0;
	else
		return -EINVAL;

	pr_info("[monitor_wmi] Запрос: %s monitor mode\n",
		val ? "включить" : "выключить");

	g_work_val = val;
	schedule_work(&g_work);

	return count;
}

static ssize_t proc_read(struct file *f, char __user *buf,
			 size_t count, loff_t *pos)
{
	char status[128];
	int len;

	if (*pos > 0)
		return 0;

	len = snprintf(status, sizeof(status),
		"handle_captured=%d current_mode=%d\n"
		"usage: echo 1 > /proc/monitor_wmi (on)\n"
		"       echo 0 > /proc/monitor_wmi (off)\n",
		g_handle_captured ? 1 : 0,
		g_current_mode);

	if (count < len)
		return -EINVAL;
	if (copy_to_user(buf, status, len))
		return -EFAULT;

	*pos = len;
	return len;
}

static const struct proc_ops proc_fops = {
	.proc_read  = proc_read,
	.proc_write = proc_write,
};

static struct proc_dir_entry *g_proc_entry = NULL;

/* ─── Module init / exit ────────────────────────────────────────────────── */

static int __init monitor_wmi_init(void)
{
	int ret;

	pr_info("[monitor_wmi] Загрузка модуля...\n");

	/* Ищем WMI функции через kallsyms */
	g_buf_alloc = (fn_wmi_buf_alloc_t)
		kallsyms_lookup_name("wmi_buf_alloc_fl");
	g_buf_free  = (fn_wmi_buf_free_t)
		kallsyms_lookup_name("wmi_buf_free");
	g_cmd_send  = (fn_wmi_cmd_send_t)
		kallsyms_lookup_name("wmi_unified_cmd_send_over_qmi");

	if (!g_buf_alloc) {
		pr_err("[monitor_wmi] wmi_buf_alloc_fl не найдена в kallsyms\n");
		return -ENOENT;
	}
	if (!g_buf_free) {
		pr_err("[monitor_wmi] wmi_buf_free не найдена\n");
		return -ENOENT;
	}
	if (!g_cmd_send) {
		pr_err("[monitor_wmi] wmi_unified_cmd_send_over_qmi не найдена\n");
		return -ENOENT;
	}

	pr_info("[monitor_wmi] wmi_buf_alloc_fl:             %px\n", g_buf_alloc);
	pr_info("[monitor_wmi] wmi_buf_free:                 %px\n", g_buf_free);
	pr_info("[monitor_wmi] wmi_unified_cmd_send_over_qmi:%px\n", g_cmd_send);

	/* Регистрируем kprobe (изначально выключен) */
	g_kp.pre_handler = kprobe_pre_handler;
	ret = register_kprobe(&g_kp);
	if (ret) {
		pr_err("[monitor_wmi] register_kprobe вернул %d\n", ret);
		return ret;
	}
	disable_kprobe(&g_kp);
	pr_info("[monitor_wmi] kprobe зарегистрирован (неактивен)\n");

	/* Инициализируем work */
	INIT_WORK(&g_work, send_work_fn);

	/* Создаём /proc/monitor_wmi */
	g_proc_entry = proc_create("monitor_wmi", 0666, NULL, &proc_fops);
	if (!g_proc_entry) {
		pr_err("[monitor_wmi] proc_create вернул NULL\n");
		unregister_kprobe(&g_kp);
		return -ENOMEM;
	}

	pr_info("[monitor_wmi] Готов!\n");
	pr_info("[monitor_wmi] Включить:  echo 1 > /proc/monitor_wmi\n");
	pr_info("[monitor_wmi] Выключить: echo 0 > /proc/monitor_wmi\n");

	return 0;
}

static void __exit monitor_wmi_exit(void)
{
	pr_info("[monitor_wmi] Выгрузка...\n");

	cancel_work_sync(&g_work);

	/* Выключаем monitor mode перед выгрузкой */
	if (g_current_mode == 1 && g_handle_captured)
		do_send_monitor_cmd(0);

	unregister_kprobe(&g_kp);

	if (g_proc_entry)
		proc_remove(g_proc_entry);

	pr_info("[monitor_wmi] Выгружен\n");
}

module_init(monitor_wmi_init);
module_exit(monitor_wmi_exit);
