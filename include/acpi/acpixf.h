/******************************************************************************
 *
 * Name: acpixf.h - External interfaces to the ACPI subsystem
 *
 *****************************************************************************/

/*
 * Copyright (C) 2000 - 2013, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef __ACXFACE_H__
#define __ACXFACE_H__

/* Current ACPICA subsystem version in YYYYMMDD format */

#define ACPI_CA_VERSION                 0x20130517

#include <acpi/acconfig.h>
#include <acpi/actypes.h>
#include <acpi/actbl.h>
#include <acpi/acbuffer.h>

extern u8 acpi_gbl_permanent_mmap;

/*
 * Globals that are publically available
 */
extern u32 acpi_current_gpe_count;
extern struct acpi_table_fadt acpi_gbl_FADT;
extern u8 acpi_gbl_system_awake_and_running;
extern u8 acpi_gbl_reduced_hardware;	/* ACPI 5.0 */
extern u8 acpi_gbl_osi_data;

/* Runtime configuration of debug print levels */

extern u32 acpi_dbg_level;
extern u32 acpi_dbg_layer;

/* ACPICA runtime options */

extern u8 acpi_gbl_all_methods_serialized;
extern u8 acpi_gbl_copy_dsdt_locally;
extern u8 acpi_gbl_create_osi_method;
extern u8 acpi_gbl_disable_auto_repair;
extern u8 acpi_gbl_disable_ssdt_table_load;
extern u8 acpi_gbl_do_not_use_xsdt;
extern u8 acpi_gbl_verify_table_checksum;
extern acpi_name acpi_gbl_trace_method_name;
extern u32 acpi_gbl_trace_flags;
extern u8 acpi_gbl_enable_aml_debug_object;
extern u8 acpi_gbl_enable_interpreter_slack;
extern acpi_name acpi_gbl_trace_method_name;
extern u8 acpi_gbl_truncate_io_addresses;
extern u8 acpi_gbl_use_default_register_widths;
extern u8 acpi_gbl_disable_ssdt_table_install;

/*
 * Hardware-reduced prototypes. All interfaces that use these macros will
 * be configured out of the ACPICA build if the ACPI_REDUCED_HARDWARE flag
 * is set to TRUE.
 */
#if (!ACPI_REDUCED_HARDWARE)
#define ACPI_HW_DEPENDENT_RETURN_STATUS(prototype) \
	ACPI_EXTERNAL_RETURN_STATUS(prototype)

#define ACPI_HW_DEPENDENT_RETURN_OK(prototype) \
	ACPI_EXTERNAL_RETURN_OK(prototype)

#define ACPI_HW_DEPENDENT_RETURN_VOID(prototype) \
	ACPI_EXTERNAL_RETURN_VOID(prototype)

#else
#define ACPI_HW_DEPENDENT_RETURN_STATUS(prototype) \
	static ACPI_INLINE prototype {return(AE_NOT_CONFIGURED);}

#define ACPI_HW_DEPENDENT_RETURN_OK(prototype) \
	static ACPI_INLINE prototype {return(AE_OK);}

#define ACPI_HW_DEPENDENT_RETURN_VOID(prototype) \
	static ACPI_INLINE prototype {}

#endif				/* !ACPI_REDUCED_HARDWARE */

/* ACPICA prototypes */

#ifndef ACPI_EXTERNAL_RETURN_STATUS
#define ACPI_EXTERNAL_RETURN_STATUS(prototype) \
	prototype;
#endif

#ifndef ACPI_EXTERNAL_RETURN_OK
#define ACPI_EXTERNAL_RETURN_OK(prototype) \
	prototype;
#endif

#ifndef ACPI_EXTERNAL_RETURN_VOID
#define ACPI_EXTERNAL_RETURN_VOID(prototype) \
	prototype;
#endif

#ifndef ACPI_EXTERNAL_RETURN_UINT32
#define ACPI_EXTERNAL_RETURN_UINT32(prototype) \
	prototype;
#endif

#ifndef ACPI_EXTERNAL_RETURN_PTR
#define ACPI_EXTERNAL_RETURN_PTR(prototype) \
	prototype;
#endif

extern u32 acpi_rsdt_forced;
/*
 * Initialization
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_initialize_tables(struct acpi_table_desc
						   *initial_storage,
						   u32 initial_table_count,
						   u8 allow_resize))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status __init acpi_initialize_subsystem(void))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_enable_subsystem(u32 flags))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status __init
			    acpi_initialize_objects(u32 flags))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status __init acpi_terminate(void))

/*
 * Miscellaneous global interfaces
 */
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_enable(void))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_disable(void))
#ifdef ACPI_FUTURE_USAGE
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_subsystem_status(void))
#endif

#ifdef ACPI_FUTURE_USAGE
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_system_info(struct acpi_buffer
						 *ret_buffer))
#endif
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_statistics(struct acpi_statistics *stats))
ACPI_EXTERNAL_RETURN_PTR(const char
			  *acpi_format_exception(acpi_status exception))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_purge_cached_objects(void))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_install_interface(acpi_string interface_name))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_remove_interface(acpi_string interface_name))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_update_interfaces(u8 action))

ACPI_EXTERNAL_RETURN_UINT32(u32
			    acpi_check_address_range(acpi_adr_space_type
						     space_id,
						     acpi_physical_address
						     address, acpi_size length,
						     u8 warn))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_decode_pld_buffer(u8 *in_buffer,
						    acpi_size length,
						    struct acpi_pld_info
						    **return_buffer))

/*
 * ACPI table load/unload interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status __init
			    acpi_install_table(acpi_physical_address address,
					       u8 physical))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_load_table(struct acpi_table_header *table))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_unload_parent_table(acpi_handle object))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status __init acpi_load_tables(void))

/*
 * ACPI table manipulation interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_reallocate_root_table(void))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_find_root_pointer(acpi_size * rsdp_address))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_unload_table_id(acpi_owner_id id))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_table_header(acpi_string signature,
						  u32 instance,
						  struct acpi_table_header
						  *out_table_header))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_table_with_size(acpi_string signature,
						     u32 instance,
						     struct acpi_table_header
						     **out_table,
						     acpi_size *tbl_size))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_table(acpi_string signature, u32 instance,
					    struct acpi_table_header
					    **out_table))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_table_by_index(u32 table_index,
						     struct acpi_table_header
						     **out_table))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_install_table_handler(acpi_table_handler
							handler, void *context))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_remove_table_handler(acpi_table_handler
						       handler))

/*
 * Namespace and name interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_walk_namespace(acpi_object_type type,
						acpi_handle start_object,
						u32 max_depth,
						acpi_walk_callback
						pre_order_visit,
						acpi_walk_callback
						post_order_visit,
						void *context,
						void **return_value))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_devices(const char *HID,
					      acpi_walk_callback user_function,
					      void *context,
					      void **return_value))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_name(acpi_handle object, u32 name_type,
					   struct acpi_buffer *ret_path_ptr))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_handle(acpi_handle parent,
					     acpi_string pathname,
					     acpi_handle * ret_handle))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_attach_data(acpi_handle object,
					      acpi_object_handler handler,
					      void *data))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_detach_data(acpi_handle object,
					      acpi_object_handler handler))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_data_full(acpi_handle object,
						acpi_object_handler handler,
						void **data,
						void (*callback)(void *)))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_data(acpi_handle object,
					   acpi_object_handler handler,
					   void **data))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_debug_trace(char *name, u32 debug_level,
					      u32 debug_layer, u32 flags))

/*
 * Object manipulation and enumeration
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_evaluate_object(acpi_handle object,
						 acpi_string pathname,
						 struct acpi_object_list
						 *parameter_objects,
						 struct acpi_buffer
						 *return_object_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_evaluate_object_typed(acpi_handle object,
							acpi_string pathname,
							struct acpi_object_list
							*external_params,
							struct acpi_buffer
							*return_buffer,
							acpi_object_type
							return_type))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_object_info(acpi_handle object,
						  struct acpi_device_info
						  **return_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_install_method(u8 *buffer))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_next_object(acpi_object_type type,
						 acpi_handle parent,
						 acpi_handle child,
						 acpi_handle * out_handle))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_type(acpi_handle object,
					  acpi_object_type * out_type))


ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_id(acpi_handle object,
					acpi_owner_id * out_type))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_parent(acpi_handle object,
					    acpi_handle * out_handle))

/*
 * Handler interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_install_initialization_handler
			    (acpi_init_handler handler, u32 function))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_install_global_event_handler
				(acpi_gbl_event_handler handler, void *context))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_install_fixed_event_handler(u32
								  acpi_event,
								  acpi_event_handler
								  handler,
								  void
								  *context))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_remove_fixed_event_handler(u32 acpi_event,
								 acpi_event_handler
								 handler))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_install_gpe_handler(acpi_handle
							  gpe_device,
							  u32 gpe_number,
							  u32 type,
							  acpi_gpe_handler
							  address,
							  void *context))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_remove_gpe_handler(acpi_handle gpe_device,
							 u32 gpe_number,
							 acpi_gpe_handler
							 address))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_install_notify_handler(acpi_handle device,
							 u32 handler_type,
							 acpi_notify_handler
							 handler,
							 void *context))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_remove_notify_handler(acpi_handle device,
							u32 handler_type,
							acpi_notify_handler
							handler))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_install_address_space_handler(acpi_handle
								device,
								acpi_adr_space_type
								space_id,
								acpi_adr_space_handler
								handler,
								acpi_adr_space_setup
								setup,
								void *context))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_remove_address_space_handler(acpi_handle
							       device,
							       acpi_adr_space_type
							       space_id,
							       acpi_adr_space_handler
							       handler))
#ifdef ACPI_FUTURE_USAGE
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_install_exception_handler
			     (acpi_exception_handler handler))
#endif
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_install_interface_handler
			     (acpi_interface_handler handler))

/*
 * Global Lock interfaces
 */
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_acquire_global_lock(u16 timeout,
							 u32 *handle))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_release_global_lock(u32 handle))

/*
 * Interfaces to AML mutex objects
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_acquire_mutex(acpi_handle handle,
					       acpi_string pathname,
					       u16 timeout))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_release_mutex(acpi_handle handle,
					       acpi_string pathname))

/*
 * Fixed Event interfaces
 */
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_enable_event(u32 event, u32 flags))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_disable_event(u32 event, u32 flags))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_clear_event(u32 event))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_get_event_status(u32 event,
						      acpi_event_status
						      *event_status))
/*
 * General Purpose Event (GPE) Interfaces
 */
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_update_all_gpes(void))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_enable_gpe(acpi_handle gpe_device,
						u32 gpe_number))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_disable_gpe(acpi_handle gpe_device,
						 u32 gpe_number))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_clear_gpe(acpi_handle gpe_device,
					       u32 gpe_number))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_set_gpe(acpi_handle gpe_device,
					     u32 gpe_number, u8 action))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_finish_gpe(acpi_handle gpe_device,
						u32 gpe_number))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_mask_gpe(acpi_handle gpe_device,
					      u32 gpe_number, u8 is_masked))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_setup_gpe_for_wake(acpi_handle
							parent_device,
							acpi_handle gpe_device,
							u32 gpe_number))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_set_gpe_wake_mask(acpi_handle gpe_device,
							u32 gpe_number,
							u8 action))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_get_gpe_status(acpi_handle gpe_device,
						     u32 gpe_number,
						     acpi_event_status
						     *event_status))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_disable_all_gpes(void))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_enable_all_runtime_gpes(void))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_get_gpe_device(u32 gpe_index,
						    acpi_handle * gpe_device))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_install_gpe_block(acpi_handle gpe_device,
						       struct
						       acpi_generic_address
						       *gpe_block_address,
						       u32 register_count,
						       u32 interrupt_number))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				 acpi_remove_gpe_block(acpi_handle gpe_device))

/*
 * Resource interfaces
 */
typedef
acpi_status(*acpi_walk_resource_callback) (struct acpi_resource * resource,
					   void *context);

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_vendor_resource(acpi_handle device,
						     char *name,
						     struct acpi_vendor_uuid
						     *uuid,
						     struct acpi_buffer
						     *ret_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_current_resources(acpi_handle device,
							struct acpi_buffer
							*ret_buffer))
#ifdef ACPI_FUTURE_USAGE
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_possible_resources(acpi_handle device,
							 struct acpi_buffer
							 *ret_buffer))
#endif
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_event_resources(acpi_handle device_handle,
						      struct acpi_buffer
						      *ret_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_walk_resource_buffer(struct acpi_buffer
						       *buffer,
						       acpi_walk_resource_callback
						       user_function,
						       void *context))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_walk_resources(acpi_handle device, char *name,
						 acpi_walk_resource_callback
						 user_function, void *context))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_set_current_resources(acpi_handle device,
							struct acpi_buffer
							*in_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_get_irq_routing_table(acpi_handle device,
							struct acpi_buffer
							*ret_buffer))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_resource_to_address64(struct acpi_resource
							*resource,
							struct
							acpi_resource_address64
							*out))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			     acpi_buffer_to_resource(u8 *aml_buffer,
						     u16 aml_buffer_length,
						     struct acpi_resource
						     **resource_ptr))

/*
 * Hardware (ACPI device) interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_reset(void))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_read(u64 *value,
				      struct acpi_generic_address *reg))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_write(u64 value,
				       struct acpi_generic_address *reg))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_read_bit_register(u32 register_id,
						       u32 *return_value))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_write_bit_register(u32 register_id,
							u32 value))

/*
 * Sleep/Wake interfaces
 */
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_get_sleep_type_data(u8 sleep_state,
						     u8 *slp_typ_a,
						     u8 *slp_typ_b))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_enter_sleep_state_prep(u8 sleep_state))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_enter_sleep_state(u8 sleep_state))
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_enter_sleep_state_s4bios(void))

ACPI_EXTERNAL_RETURN_STATUS(acpi_status
			    acpi_leave_sleep_state_prep(u8 sleep_state))
ACPI_EXTERNAL_RETURN_STATUS(acpi_status acpi_leave_sleep_state(u8 sleep_state))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_set_firmware_waking_vector(u32
								physical_address))

#if ACPI_MACHINE_WIDTH == 64
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_set_firmware_waking_vector64(u64
								  physical_address))
#endif
/*
 * ACPI Timer interfaces
 */
#ifdef ACPI_FUTURE_USAGE
ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_get_timer_resolution(u32 *resolution))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status acpi_get_timer(u32 *ticks))

ACPI_HW_DEPENDENT_RETURN_STATUS(acpi_status
				acpi_get_timer_duration(u32 start_ticks,
							u32 end_ticks,
							u32 *time_elapsed))
#endif				/* ACPI_FUTURE_USAGE */

/*
 * Error/Warning output
 */
void ACPI_INTERNAL_VAR_XFACE
acpi_error(const char *module_name,
	   u32 line_number, const char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_exception(const char *module_name,
	       u32 line_number,
	       acpi_status status, const char *format, ...) ACPI_PRINTF_LIKE(4);

void ACPI_INTERNAL_VAR_XFACE
acpi_warning(const char *module_name,
	     u32 line_number, const char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_info(const char *module_name,
	  u32 line_number, const char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_bios_error(const char *module_name,
		u32 line_number, const char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_bios_warning(const char *module_name,
		  u32 line_number, const char *format, ...) ACPI_PRINTF_LIKE(3);

/*
 * Debug output
 */
#ifdef ACPI_DEBUG_OUTPUT

void ACPI_INTERNAL_VAR_XFACE
acpi_debug_print(u32 requested_debug_level,
		 u32 line_number,
		 const char *function_name,
		 const char *module_name,
		 u32 component_id, const char *format, ...) ACPI_PRINTF_LIKE(6);

void ACPI_INTERNAL_VAR_XFACE
acpi_debug_print_raw(u32 requested_debug_level,
		     u32 line_number,
		     const char *function_name,
		     const char *module_name,
		     u32 component_id,
		     const char *format, ...) ACPI_PRINTF_LIKE(6);
#endif

/*
 * Application prototypes
 *
 * All interfaces used by application will be configured
 * out of the ACPICA build unless the ACPI_APPLICATION
 * flag is defined.
 */
#ifdef ACPI_APPLICATION
#define ACPI_APP_DEPENDENT_RETURN_VOID(prototype) \
	prototype;

#else
#define ACPI_APP_DEPENDENT_RETURN_VOID(prototype) \
	static ACPI_INLINE prototype {return;}

#endif				/* ACPI_APPLICATION */

#endif				/* __ACXFACE_H__ */
