/*
 * Copyright (C) 2018 Sören Tempel <tempel@uni-bremen.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    core_checkedc Checked C
 * @ingroup     core
 * @brief       Support for the Checked C language extension
 *
 * @{
 * @file
 * @brief       Wrappers for keywords used by the Checked C extension
 *
 * @details     If *USE_CHECKEDC* is defined all keywords of the
 *              Checked C language extension are enabled causing code
 *              using them to be compiled with bounds checks. This
 *              header file provides roughly the same macros as the
 *              `stdchecked.h`, with the exception that the macros are
 *              ignored when *USE_CHECKEDC* is not defined.
 *
 * @author      Sören Tempel <tempel@uni-bremen.de>
 */

#ifndef CHECKEDC_H
#define CHECKEDC_H

/**
 * @def annotate
 *
 * @brief Add a type or bounds annotation using expression @p e.
 */
#ifdef USE_CHECKEDC
#define annotate(e) : e
#else
#define annotate(e)
#endif

/**
 * @def abounds
 *
 * @brief Add a bounds annotation using expression @p e1 and @p e2.
 *
 * This macro is just a shortcut which uses the ::annotate macro.
 */
#define abounds(e1, e2) annotate(bounds(e1, e2))

/**
 * @def abyte_count
 *
 * @brief Add a byte_count annotation using expression @p e.
 *
 * This macro is just a shortcut which use the ::annotate macro.
 */
#define abyte_count(e) annotate(byte_count(e))

/**
 * @def acount
 *
 * @brief Add a count annotation using expression @p e.
 *
 * This macro is just a shortcut which uses the ::annotate macro.
 */
#define acount(e) annotate(count(e))

/**
 * @def assume_bounds_cast
 *
 * @brief Perform an unsafe cast to type @p t.
 */
#ifdef USE_CHECKEDC
#define assume_bounds_cast(t, ...) _Assume_bounds_cast<t>(__VA_ARGS__)
#else
#define assume_bounds_cast(...)
#endif

/**
 * @def assume_cast
 *
 * @brief Perform an unsafe cast to type @p t for expression @p e.
 *
 * This function is a shortcut for ::assume_bounds_cast wit the
 * exception that it also generates code for casting types when
 * *USE_CHECKEDC* is unset.
 */
#ifdef USE_CHECKEDC
#define assume_cast(t, e) assume_bounds_cast(t, e)
#else
#define assume_cast(t, e) (t)e
#endif

/**
 * @def atype
 *
 * @brief Add a type annotation using expression @p e.
 *
 * This macro is just a shortcut which uses the ::annotate macro.
 */
#define atype(e) annotate(itype(e))

/**
 * @def array_ptr
 *
 * @brief Declare a pointer to an element of an array of
 *        type @p t values.
 */
#ifdef USE_CHECKEDC
#define array_ptr(t) _Array_ptr<t>
#else
#define array_ptr(t) ptr(t)
#endif

/**
 * @def checked
 *
 * @brief Declare an unchecked program scope.
 */
#ifdef USE_CHECKEDC
#define checked _Checked
#else
#define checked
#endif

/**
 * @def dynamic_bounds_cast
 *
 * @brief Perform a cast to type @p t with a dynamic bounds check.
 */
#ifdef USE_CHECKEDC
#define dynamic_bounds_cast(t, ...) _Dynamic_bounds_cast<t>(__VA_ARGS__)
#else
#define dynamic_bounds_cast(...)
#endif

/**
 * @def dynamic_cast
 *
 * @brief Perform a cast to type @p t for expression @p e.
 *
 * This function is a shortcut for ::dynamic_bounds_cast with the
 * exception that it also generates code for casting types when
 * *USE_CHECKEDC* is unset.
 */
#ifdef USE_CHECKEDC
#define dynamic_cast(t, e) dynamic_bounds_cast(t, e)
#else
#define dynamic_cast(t, e) (t)e
#endif

/**
 * @def dynamic_check
 *
 * @brief Insert a custom dynamic check.
 *
 * Use this macro to check a boolean condition @p c and generate a
 * runtime error if it fails. This macro has no effect when
 * *USE_CHECKEDC* is not defined. Refer to section 2.9 of the Checked C
 * language specification for more information on dynamic checks.
 */
#ifdef USE_CHECKEDC
#define dynamic_check(c) _Dynamic_check(c)
#else
#define dynamic_check(c)
#endif

/**
 * @def nt_array_ptr
 *
 * @brief Declare a pointer to an element of a null-terminated
 *        array of type @p t values.
 */
#ifdef USE_CHECKEDC
#define nt_array_ptr(t) _Nt_array_ptr<t>
#else
#define nt_array_ptr(t) ptr(t)
#endif

/**
 * @def nt_checked
 *
 * @brief Declare a null-terminated array.
 */
#ifdef USE_CHECKEDC
#define nt_checked _Nt_checked
#else
#define nt_checked
#endif

/**
 * @def ptr
 *
 * @brief Declare a pointer to a value of type @p t.
 */
#ifdef USE_CHECKEDC
#define ptr(t) _Ptr<t>
#else
#define ptr(t) t *
#endif

/**
 * @def unchecked
 *
 * @brief Declare an unchecked program scope.
 *
 * Use this macro to define an unchecked program scope. When
 * *USE_CHECKEDC* is unset this macro doesn't have any effect if it is
 * set it can be used in all places where the ::checked macro can be
 * used. Refer to section 2.8 of the Checked C language specification
 * for more information on program scopes.
 */
#ifdef USE_CHECKEDC
#define unchecked _Unchecked
#else
#define unchecked
#endif

#endif
/** @} */
