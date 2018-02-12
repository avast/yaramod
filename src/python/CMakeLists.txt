pybind11_add_module(yaramod-python
	yaramod_python.cpp
	py_visitor.cpp
)

set_target_properties(yaramod-python PROPERTIES OUTPUT_NAME "yaramod")
target_link_libraries(yaramod-python PUBLIC yaramod)
