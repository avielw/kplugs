#include "types.h"

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");

#include "env.h"
#include "context.h"
#include "function.h"
#include "vm.h"


#define DEVICE_NAME			"kplugs"

context_t *GLOBAL_CONTEXT = NULL;

/* choose the correct errno value to return, and create an answer */
static int create_error(context_t *cont, int err)
{
	if (NULL != cont) {
		 context_create_reply(cont, (err < 0) ? -err : err, NULL);
	}

	switch (err) {
	case ERROR_OK:
		return 0;

	case ERROR_POINT:
	case -ERROR_POINT:
		return -EFAULT;

	case ERROR_MEM:
	case -ERROR_MEM:
		return -ENOMEM;

	default:
		return -EINVAL;
	}
}

/* kplugs device callbacks: */

/* open callback */
static int kplugs_open(struct inode *inode, struct file *filp)
{
	int err = 0;

	if (!capable(CAP_SYS_MODULE)) {
		return -EPERM;
	}

	/* create a new context for this file descriptor */
	err = context_create((context_t **)&filp->private_data);

	return err ? create_error(NULL, err) : 0;
}


/* release callback */
static int kplugs_release(struct inode *inode, struct file *filp)
{
	if (filp->private_data) {
		/* free this file's context */
		context_free((context_t *)filp->private_data);
		filp->private_data = NULL;
	}
	return 0;
}

/* read callback */
static ssize_t kplugs_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	context_t *cont = (context_t *)filp->private_data;

	return context_get_reply(cont, buf, count);
}

/* write callback */
static ssize_t kplugs_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	kplugs_command_t cmd;
	context_t *file_cont = NULL;
	context_t *cont = NULL;
	bytecode_t *code = NULL;
	function_t *func = NULL;
	exception_t excep;
	kpstack_t stack;
	word iter, arg;
	word args;
	byte little_endian;
	byte func_name[MAX_FUNC_NAME + 1];
	int err = 0;

#ifdef __LITTLE_ENDIAN
	little_endian = 1;
#else
	little_endian = 0;
#endif
	file_cont = (context_t *)filp->private_data;

	if (count < sizeof(byte) * 3) { /* three bytes of header */
		return create_error(file_cont, -ERROR_PARAM);
	}

	err = memory_copy_from_outside(&cmd, buf, count < sizeof(kplugs_command_t) ? count : sizeof(kplugs_command_t));
	if (err < 0) {
		return create_error(file_cont, err);
	}

	if (cmd.word_size != sizeof(word) || cmd.l_endian != little_endian) {
		return create_error(file_cont, -ERROR_ARCH);
	}

	if (cmd.version_major != VERSION_MAJOR || cmd.version_minor != VERSION_MINOR) {
		return create_error(file_cont, -ERROR_VERSION);
	}

	if (count != sizeof(kplugs_command_t)) {
		return create_error(file_cont, -ERROR_PARAM);
	}

	cont = cmd.is_global ? GLOBAL_CONTEXT : file_cont;

	switch (cmd.type) {
	case KPLUGS_LOAD:
		/* load a new function */

		if (cmd.len2 != 0 || cmd.ptr2 != NULL) {
			return create_error(file_cont, -ERROR_PARAM);
		}

		code = memory_alloc(cmd.len1);
		if (NULL == code) {
			ERROR(create_error(file_cont, -ERROR_MEM));
		}

		err = memory_copy_from_outside(code, cmd.uptr1, cmd.len1);
		if (err < 0) {
			err = create_error(file_cont, err);
			goto clean;
		}

		/* create the function */
		err = function_create(code, cmd.len1, &func);
		if (err < 0) {
			err = create_error(file_cont, err);
			goto clean;
		}

		err = context_add_function(cont, func);
		if (err < 0) {
			err = create_error(file_cont, err);
			goto clean;
		}

		/* return the function's address */
		context_create_reply(file_cont, (word)&func->func_code, NULL);

		return count;

	case KPLUGS_UNLOAD:
		/* unload a function with a name */
		if (NULL != cmd.uptr2) {
			return create_error(file_cont, -ERROR_PARAM);
		}
	case KPLUGS_EXECUTE:
		/* execute (and unload) a function with a name */
		if (cmd.len1 > MAX_FUNC_NAME || (cmd.len2 % sizeof(word)) != 0) {
			return create_error(file_cont, -ERROR_PARAM);
		}

		err = memory_copy_from_outside(func_name, cmd.uptr1, cmd.len1);
		if (err < 0) {
			return create_error(file_cont, err);
		}

		func_name[cmd.len1] = '\0';

		/* find the function */

		if (cmd.type == KPLUGS_UNLOAD) {
			func = context_find_function(cont, func_name);
			if (NULL == func) {
				return create_error(file_cont, -ERROR_UFUNC);
			}
			/* delete the function */
			context_free_function(func);
			err = (int)count;

			goto clean;
		}

		if (!cmd.is_global) {
			func = context_find_function(file_cont, func_name);
		}
		if (NULL == func) {
			func = context_find_function(GLOBAL_CONTEXT, func_name);
			if (NULL == func) {
				return create_error(file_cont, -ERROR_UFUNC);
			}
		}

		goto execute_func;

	case KPLUGS_UNLOAD_ANONYMOUS:
		/* unload an anonymous function */
		if (NULL != cmd.uptr2 || cmd.len1 || cmd.len2) {
			return create_error(file_cont, -ERROR_PARAM);
		}
		func = context_find_anonymous(cont, cmd.ptr1);
		if (NULL == func) {
			return create_error(file_cont, -ERROR_UFUNC);
		}

		/* delete the function */
		context_free_function(func);

		err = (int)count;
		goto clean;
	break;

	case KPLUGS_EXECUTE_ANONYMOUS:
		/* execute (and unload) an anonymous function */
		if (cmd.len1 || (cmd.len2 % sizeof(word)) != 0) {
			return create_error(file_cont, -ERROR_PARAM);
		}

		/* find the function */
		if (!cmd.is_global) {
			func = context_find_anonymous(file_cont, cmd.ptr1);
		}
		if (NULL == func) {
			func = context_find_anonymous(GLOBAL_CONTEXT, cmd.ptr1);
			if (NULL == func) {
				return create_error(file_cont, -ERROR_UFUNC);
			}
		}

execute_func:
		/* do the execution of a function: */

		args = cmd.len2 / sizeof(word);
		if (args > func->num_maxargs || args < func->num_minargs) {
			ERROR_CLEAN(create_error(file_cont, -ERROR_ARGS));
		}

		err = stack_alloc(&stack, sizeof(word), CALL_STACK_SIZE);
		if (err < 0) {
			err = create_error(file_cont, err);
			goto clean;
		}

		/* push the arguments to a stack */
		for (iter = 0; iter < args; ++iter) {
			err = memory_copy_from_outside(&arg, cmd.ptr2 + (iter * sizeof(word)), sizeof(arg));
			if (err < 0) {
				stack_free(&stack);
				err = create_error(file_cont, err);
				goto clean;
			}

			if (NULL == stack_push(&stack, &arg)) {
				stack_free(&stack);
				ERROR_CLEAN(create_error(file_cont, -ERROR_MEM));
			}
		}

		/* execute the function and create an answer */
		arg = vm_run_function(func, &stack, &excep);

		stack_free(&stack);

		if (excep.had_exception) {
			err = -EINVAL; /* it dosen't really matter which error. the value of the error will be taken from the answer */
			arg = excep.value;
		} else {
			err = (int)count;
		}

		context_create_reply(file_cont, arg, &excep);

		goto clean;

	case KPLUGS_GET_LAST_EXCEPTION:
		if (NULL != cmd.uptr2 || cmd.len1 < sizeof(exception_t) || cmd.len2) {
			ERROR(create_error(file_cont, -ERROR_PARAM));
		}

		err = context_get_last_exception(file_cont, (exception_t *)cmd.ptr1);
		if (err < 0) {
			return create_error(file_cont, err);
		}

		return count;

	default:
		return create_error(file_cont, -ERROR_PARAM);
	}
clean:
	if (NULL != func) {
		function_put(func);
	} else if (NULL != code) {
		memory_free(code);
	}
	return err;
}

/* the device operations */
static struct file_operations kplugs_ops =
{
		.owner = THIS_MODULE,
		.open = kplugs_open,
		.release = kplugs_release,
		.read = kplugs_read,
		.write = kplugs_write,
};

static dev_t kplugs_devno = 0;
static struct cdev *kplugs_cdev= NULL;
static struct class *kplugs_class = NULL;

/* the module init function */
static int __init kplugs_init(void)
{
	int err = 0;
	struct device *device = NULL;

	memory_start();

	err = context_create(&GLOBAL_CONTEXT);
	if (err < 0) {
		output_string("Couldn't create the global context.\n");
		ERROR_CLEAN(create_error(NULL, err));
	}

	err = alloc_chrdev_region(&kplugs_devno , 0, 1, DEVICE_NAME);
	if (err < 0) {
		output_string("Couldn't allocate a region.\n");
		ERROR_CLEAN(create_error(NULL, err));
	}

	kplugs_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (NULL == kplugs_class) {
		output_string("Couldn't create class.\n");
		ERROR_CLEAN(-ENOMEM);
	}
	
	kplugs_cdev = cdev_alloc();
	if (NULL == kplugs_cdev) {
		output_string("Couldn't allocate a cdev.\n");
		ERROR_CLEAN(-ENOMEM);
	}

	cdev_init(kplugs_cdev, &kplugs_ops);

	err = cdev_add(kplugs_cdev, kplugs_devno, 1);
	if (err < 0) {
		output_string("Couldn't add the cdev.\n");
		ERROR_CLEAN(create_error(NULL, err));
	}

	device = device_create(kplugs_class, NULL, kplugs_devno, NULL, DEVICE_NAME);
	if (device == NULL) {
		output_string("Couldn't create the device.\n");
		ERROR_CLEAN(-ENOMEM);
	}

	return 0;

clean:
	if (NULL != kplugs_cdev) {
		cdev_del(kplugs_cdev);
	}
	if (NULL != kplugs_class) {
		class_destroy(kplugs_class);
	}
	if (kplugs_devno) {
		unregister_chrdev_region(kplugs_devno, 1);
	}
	if (NULL != GLOBAL_CONTEXT) {
		context_free(GLOBAL_CONTEXT);
	}
	memory_stop();
	return err;
}

/* the module clean function */
static void __exit kplugs_exit(void)
{
	device_destroy(kplugs_class, kplugs_devno);
	cdev_del(kplugs_cdev);
	class_destroy(kplugs_class);
	unregister_chrdev_region(kplugs_devno, 1);
	context_free(GLOBAL_CONTEXT);
	memory_stop();
}

module_init(kplugs_init);
module_exit(kplugs_exit);


#else

#include "env.h"
#include "context.h"

context_t *GLOBAL_CONTEXT = NULL;

int main(void)
{
	memory_start();

	output_string("This is the user mode version.\n");
	output_string("The VM Engine works but we don't really have what to do with it.\n");
	output_string("You should know that the user mode version is just for testing, AND IS NOT THREAD SAFE!\n");

	memory_stop();

	return 0;
}

#endif

