/**
 * @file src/types/features.h
 * @brief Declaration of enum TokenType.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

namespace yaramod {

/**
 * Class representing features of Yaramod.
 */
enum Features
{
	Basic = 0x01,          // 0001 - such module is always loaded
	AvastOnly = 0x02,      // 0010 - such module is loaded when Avast specified
	VirusTotalOnly = 0x04, // 0100 - such module is loaded when VirusTotal specified
	Deprecated = 0x08,     // 1000 - such module is deprecated
	Avast = Basic | AvastOnly,           // 0011 - specification which will load all basic and Avast-specific modules
	VirusTotal = Basic | VirusTotalOnly, // 0101 - specification which will load all basic and VirusTotal-specific modules
	AllCurrent = Avast | VirusTotal,     // 0111 - specification which will load all currently used modules
	Everything = AllCurrent | Deprecated // 1111 - specification which will load everything - even old deprecated modules
};

} //namespace yaramod
