#pragma once

#include <vector>
#include <string>
#include <iostream>

#include "NNInputs.h"
#include "json11.hpp"

// Dictionary
struct KeyEntry
{
	std::string key;
	size_t count;

	bool operator () (const KeyEntry& acOther) const
	{
		return acOther.key == key;
	}
};
std::vector<std::vector<KeyEntry>> g_fieldCounts;
size_t g_totalLogEntries;
std::vector<double> g_highestTfIdf;

// Training set to learn on
struct TrainingSet
{
	TrainingSet(const std::vector<double>& acInputs, const std::vector<double>& acDesiredOutputs, const std::string& acOriginalLog, const std::filesystem::path& acPath)
		: inputs(acInputs)
		, desiredOutputs(acDesiredOutputs)
		, originalLog(acOriginalLog)
		, filePath(acPath)
	{
	}

	std::vector<double> inputs;
	std::vector<double> desiredOutputs;
	std::string originalLog;
	std::filesystem::path filePath;
};

// This is required to fit the TfIdf to neural network input ranges of 0-1
void CalculateHighestTfIdf()
{
	// Start clean
	g_highestTfIdf.clear();
	g_highestTfIdf.resize(EInputs::SIZE);

	// Find the highest TfIdf value per key by calculating every one of them
	for (size_t key = 0; key < g_fieldCounts.size(); ++key)
	{
		double highestTfIdf = 0.0;
		for (size_t i = 0; i < g_fieldCounts[key].size(); ++i)
		{
			double termFrequency = double(g_fieldCounts[key][i].count) / double(g_fieldCounts[key].size());
			double inverseDocumentFrequency = log(double(g_totalLogEntries) / double(g_fieldCounts[key].size()));
			double tfIdf = termFrequency * inverseDocumentFrequency;

			if (tfIdf > highestTfIdf)
			{
				highestTfIdf = tfIdf;
			}
		}

		g_highestTfIdf[key] = highestTfIdf;
	}
}

void AddDictionaryEntry(const std::string& acLogEntry, bool aRecalculateTfIdf)
{
	// aRecalculateTfIdf can be set to true if you want to dynamically add in new entries

	// Read JSON
	std::string error;
	auto json = json11::Json::parse(acLogEntry, error);
	if (!error.empty())
	{
		std::cout << "[ERROR] Failed to parse log: " << error << std::endl;
		return;
	}

	// Iterate through json array
	size_t keyIndex = 0;
	KeyEntry entry;
	entry.count = 1;
	for (auto& k : json.array_items())
	{
		// Get value (always last in array)
		for (auto& kv : k.array_items())
		{
			entry.key = kv.dump();
		}

		// Check if we have this key
		auto it = std::find_if(g_fieldCounts[keyIndex].begin(), g_fieldCounts[keyIndex].end(), entry);
		if (it != g_fieldCounts[keyIndex].end())
		{
			// Key exists, create the count
			it->count++;
		}
		else
		{
			// Key doesn't exist, use default count and the new value
			g_fieldCounts[keyIndex].push_back(entry);
		}

		// Some logs have an additional footer, but it's rare and always empty so discard this
		keyIndex++;
		if (keyIndex >= EInputs::SIZE)
		{
			break;
		}
	}

	// Increase log count
	g_totalLogEntries++;

	if (aRecalculateTfIdf)
	{
		CalculateHighestTfIdf();
	}
}

// Translate a log entry to NN inputs
std::vector<double> GetInputs(const std::string& acLogEntry)
{
	std::vector<double> ret;

	// Parse the JSON entry
	std::string error;
	auto json = json11::Json::parse(acLogEntry, error);
	if (!error.empty())
	{
		std::cout << "[ERROR] Failed to parse log: " << error << std::endl;
		return ret;
	}

	// Loop through the JSON entries to get individual input values
	size_t keyIndex = 0;
	KeyEntry entry;
	entry.count = 1;
	for (auto& k : json.array_items())
	{
		//std::cout << k.dump() << std::endl;
		for (auto& kv : k.array_items())
		{
			entry.key = kv.dump();
		}

		// Do we have this entry in our dictionary?
		auto it = std::find_if(g_fieldCounts[keyIndex].begin(), g_fieldCounts[keyIndex].end(), entry);
		if (it != g_fieldCounts[keyIndex].end())
		{
			// Calculate how frequent this entry value is in the dictionary for this specific field
			if (g_highestTfIdf[keyIndex] > 0.0)
			{
				double termFrequency = double(it->count) / double(g_fieldCounts[keyIndex].size());
				double inverseDocumentFrequency = log(double(g_totalLogEntries) / double(g_fieldCounts[keyIndex].size()));
				double tfIdf = 1.f / g_highestTfIdf[keyIndex] * (termFrequency * inverseDocumentFrequency);
				ret.push_back(tfIdf);
			}
			else
			{
				// Prevent division by 0
				ret.push_back(0.0);
			}
		}
		else
		{
			// Key not found - word is unknown
			ret.push_back(0.0);
		}
		
		// Some logs have additional footers that we don't need - cut them off
		keyIndex++;
		if (keyIndex >= EInputs::SIZE)
		{
			break;
		}
	}

	return ret;
}
