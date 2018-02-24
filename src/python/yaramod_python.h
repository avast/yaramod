/**
 * @file src/python/yaramod_python.h
 * @brief Main header for yaramod python bindings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <yaramod/yaramod.h>

#include <optional_lite/optional.hpp>

/**
 * Always include this file before anything else in `src/python` folder.
 * Otherwise, you'll get `template spcialization after instantiation` errors.
 */

namespace pybind11 { namespace detail {

/**
 * Type caster which allows us to use `nonstd::optional<T>` in Python. In Python, if you return
 * instance of T, it is going to set optional value to instance of T. If you return `None`, it is
 * going to set the optional value to empty value.
 */
template <typename T>
struct type_caster<nonstd::optional<T>> : public optional_caster<nonstd::optional<T>> {};

/**
 * This type caster allows us to use `std::vector<const yaramod::String*>` with `return_value_policy:reference`.
 * Originally, return value policy influenced just the vector itself but not its content. This overrides the return value policy
 * of the content.
 */
template <>
struct type_caster<std::vector<const yaramod::String*>> : list_caster<std::vector<const yaramod::String*>, const yaramod::String*>
{
	static handle cast(const std::vector<const yaramod::String*>& src, return_value_policy, handle parent)
	{
		return list_caster<std::vector<const yaramod::String*>, const yaramod::String*>::cast(src, return_value_policy::reference, parent);
	}

	static handle cast(const std::vector<const yaramod::String*>* src, return_value_policy pol, handle parent)
	{
		return cast(*src, pol, parent);
	}
};

}}
