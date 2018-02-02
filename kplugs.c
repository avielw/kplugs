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
static int create_error(kplugs_command_t *command, int err)
{
    if (command) {
        command->error = (byte)(unsigned int)(-err);
        return 0;
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

/* write callback */
static long kplugs_ioctl(struct file *filp, unsigned int cmd, unsigned long argp)
{
	kplugs_command_t command;
	dyn_mem_t dyn_head, *dyn;
	context_t *file_cont = NULL;
	context_t *cont = NULL;
	bytecode_t *code = NULL;
	function_t *func = NULL;
	kpstack_t stack;
	word iter, arg;
	word args;
	byte little_endian;
	byte func_name[MAX_FUNC_NAME + 1];
    char __user *buf = (char __user *)argp;
	void *data;
	int err = 0;

#ifdef __LITTLE_ENDIAN
	little_endian = 1;
#else
	little_endian = 0;
#endif
	file_cont = (context_t *)filp->private_data;

	err = memory_copy_from_outside(&command, buf, sizeof(command));
	if (err < 0) {
		return create_error(NULL, err);
	}

    command.excep.had_exception = 0;
	if (command.word_size != sizeof(word) || command.l_endian != little_endian) {
		err = create_error(&command, -ERROR_ARCH);
		goto clean;
	}

	if (command.version_major != VERSION_MAJOR || command.version_minor != VERSION_MINOR) {
		err = create_error(&command, -ERROR_VERSION);
		goto clean;
	}

	cont = command.is_global ? GLOBAL_CONTEXT : file_cont;

	switch (cmd) {
	case KPLUGS_LOAD:
		/* load a new function */

		if (command.len2 != 0 || command.ptr2 != NULL) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}

		code = memory_alloc(command.len1);
		if (NULL == code) {
			err = create_error(&command, -ERROR_MEM);
			goto clean;
		}

		err = memory_copy_from_outside(code, command.uptr1, command.len1);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}

		/* create the function */
		err = function_create(code, command.len1, &func);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}

		err = context_add_function(cont, func);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}

		/* return the function's address */
        command.val1 = (word)&func->func_code;
        func = NULL;
        code = NULL;
        err = 0;
        goto clean;

	case KPLUGS_UNLOAD:
		/* unload a function with a name */
		if (NULL != command.uptr2) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}
	case KPLUGS_EXECUTE:
		/* execute (and unload) a function with a name */
		if ((command.len2 % sizeof(word)) != 0) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}

	case KPLUGS_SEND_DATA:
	case KPLUGS_RECV_DATA:
		if (command.len1 > MAX_FUNC_NAME) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}

		err = memory_copy_from_outside(func_name, command.uptr1, command.len1);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}

		func_name[command.len1] = '\0';

		/* find the function */

		if (cmd == KPLUGS_EXECUTE) {
			if (!command.is_global) {
				func = context_find_function(file_cont, func_name);
			}
			if (NULL == func) {
				func = context_find_function(GLOBAL_CONTEXT, func_name);
				if (NULL == func) {
			        err = create_error(&command, -ERROR_UFUNC);
			        goto clean;
				}
			}
			goto execute_func;
		}

		func = context_find_function(cont, func_name);
		if (NULL == func) {
			err = create_error(&command, -ERROR_UFUNC);
			goto clean;
		}

		if (cmd == KPLUGS_UNLOAD) {
			goto delete_func;
		} else if (cmd == KPLUGS_SEND_DATA) {
			goto send_func;
		} else { /* KPLUGS_RECV_DATA */
			goto recv_func;
		}


	case KPLUGS_UNLOAD_ANONYMOUS:
		/* unload an anonymous function */
		if (NULL != command.uptr2 || command.len1 || command.len2) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}
		func = context_find_anonymous(cont, command.ptr1);
		if (NULL == func) {
			err = create_error(&command, -ERROR_UFUNC);
			goto clean;
		}

delete_func:
		/* delete the function */
		context_free_function(func);

		err = 0;
		goto clean;
	break;

	case KPLUGS_EXECUTE_ANONYMOUS:
		/* execute (and unload) an anonymous function */
		if (command.len1 || (command.len2 % sizeof(word)) != 0) {
			err = create_error(&command, -ERROR_PARAM);
			goto clean;
		}

		/* find the function */
		if (!command.is_global) {
			func = context_find_anonymous(file_cont, command.ptr1);
		}
		if (NULL == func) {
			func = context_find_anonymous(GLOBAL_CONTEXT, command.ptr1);
			if (NULL == func) {
			    err = create_error(&command, -ERROR_UFUNC);
			    goto clean;
			}
		}

execute_func:
		/* do the execution of a function: */

		args = command.len2 / sizeof(word);
		if (args > func->num_maxargs || args < func->num_minargs) {
			err = create_error(&command, -ERROR_ARGS);
			goto clean;
		}

		err = stack_alloc(&stack, sizeof(word), CALL_STACK_SIZE);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}

		/* push the arguments to a stack */
		for (iter = 0; iter < args; ++iter) {
			err = memory_copy_from_outside(&arg, command.ptr2 + (iter * sizeof(word)), sizeof(arg));
			if (err < 0) {
				stack_free(&stack);
				err = create_error(&command, err);
				goto clean;
			}

			if (NULL == stack_push(&stack, &arg)) {
				stack_free(&stack);
				err = create_error(&command, -ERROR_MEM);
				goto clean;
			}
		}

		/* execute the function and create an answer */
		arg = vm_run_function(func, &stack, &command.excep);

		stack_free(&stack);

        err = 0;
        command.val1 = arg;

		goto clean;

	case KPLUGS_SEND_DATA_ANONYMOUS:
		/* send to an anonymous function */

		if (!command.is_global) {
			func = context_find_anonymous(file_cont, command.ptr1);
		}
		if (NULL == func) {
			func = context_find_anonymous(GLOBAL_CONTEXT, command.ptr1);
			if (NULL == func) {
				err = create_error(&command, -ERROR_UFUNC);
				goto clean;
			}
		}

send_func:
		memory_dyn_init(&dyn_head);

		data = memory_alloc_dyn(&dyn_head, command.len2);
		if (NULL == data) {
			memory_dyn_clean(&dyn_head);
			err = create_error(&command, -ERROR_MEM);
			goto clean;
		}

		dyn = get_dyn_mem(&dyn_head, data);
		if (NULL == dyn) {
			/* we should not be here */
			memory_dyn_clean(&dyn_head);
			err = create_error(&command, -ERROR_NODYM);
			goto clean;
		}

		err = memory_copy_from_outside(data, command.uptr2, command.len2);
		if (err < 0) {
			memory_dyn_clean(&dyn_head);
			err = create_error(&command, err);
			goto clean;
		}

		err = send_data_to_other(&func->to_kernel, dyn);
		memory_dyn_clean(&dyn_head);
		if (err < 0) {
			err = create_error(&command, err);
			goto clean;
		}
		err = 0;
        command.val1 = 0;

		goto clean;

	case KPLUGS_RECV_DATA_ANONYMOUS:
		/* receive from an anonymous function */

		if (!command.is_global) {
			func = context_find_anonymous(file_cont, command.ptr1);
		}
		if (NULL == func) {
			func = context_find_anonymous(GLOBAL_CONTEXT, command.ptr1);
			if (NULL == func) {
				return create_error(&command, -ERROR_UFUNC);
			}
		}

recv_func:
		memory_dyn_init(&dyn_head);

		err = recv_data_from_other(&func->to_user, &dyn_head, &dyn);
		if (err) {
			err = create_error(&command, err);
			goto clean;
		}

		err = memory_copy_to_outside(command.uptr2, &dyn->data, dyn->size < command.len2 ? dyn->size : command.len2);
		if (err) {
			err = create_error(&command, err);
		} else {
			err = 0;
            command.val1 = dyn->size;
		}

		memory_dyn_clean(&dyn_head);
		goto clean;

	default:
		err = create_error(&command, -ERROR_PARAM);
		goto clean;
	}
clean:
	if (NULL != func) {
		function_put(func);
	} else if (NULL != code) {
		memory_free(code);
	}
    if (0 == err) {
        err = memory_copy_to_outside(buf, &command, sizeof(command));
        if (err) {
            err = create_error(NULL, err);
        }
    }
	return err;
}

/* the device operations */
static struct file_operations kplugs_ops =
{
		.owner = THIS_MODULE,
		.open = kplugs_open,
		.release = kplugs_release,
		.unlocked_ioctl = kplugs_ioctl,
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

