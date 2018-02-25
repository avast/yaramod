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
#include <variant/variant.hpp>

/**
 * Always include this file before anything else in `src/python` folder.
 * Otherwise, you'll get `template spcialization after instantiation` errors.
 */

namespace pybind11 { namespace detail {

/**
 * Type caster which allows us to use `mpark::variant<Ts...>` in Python. In Python, the variable
 * is always going to have set its proper type. No visit is required.
 */
template <typename... Ts>
struct type_caster<mpark::variant<Ts...>> : variant_caster<mpark::variant<Ts...>> {};

/**
 * Helper for type caster of `mpark::variant` to inspect values of variant.
 */
template <>
struct visit_helper<mpark::variant>
{
	template <typename... Args>
	static auto call(Args&&... args) -> decltype(mpark::visit(args...))
	{
		return mpark::visit(args...);
	}
};

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
