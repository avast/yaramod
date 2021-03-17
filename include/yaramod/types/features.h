/**
 * @file src/types/features.h
 * @brief Declaration of enum Features.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

namespace yaramod {

/**
 * Class representing features of Yaramod.
 */
enum Features
{
	Basic = 0x01,          // 0001 - such object is always consider
	AvastOnly = 0x02,      // 0010 - such object is consider when Avast specified
	VirusTotalOnly = 0x04, // 0100 - such object is consider when VirusTotal specified
	Deprecated = 0x08,     // 1000 - such object is deprecated
	Avast = Basic | AvastOnly,           // 0011 - specification which will consider all basic and Avast-specific objects
	VirusTotal = Basic | VirusTotalOnly, // 0101 - specification which will consider all basic and VirusTotal-specific objects
	AllCurrent = Avast | VirusTotal,     // 0111 - specification which will consider all currently used objects
	Everything = AllCurrent | Deprecated // 1111 - specification which will consider everything - even old deprecated objects
};

} //namespace yaramod
