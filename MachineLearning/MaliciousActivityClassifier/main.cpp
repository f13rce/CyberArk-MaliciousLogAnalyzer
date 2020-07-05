#include <iostream>

#include <iostream>
#include <string>
#include <algorithm>
#include <filesystem>
#include <fstream>

#include <algorithm>
#include <random>
#include <cstdlib>

#include <thread>
#include <mutex>
#include <chrono>

#include "genann.h"
#include "NNInputs.h"
#include "Techniques.h"
#include "TrainingSet.h"

struct AnalyzeOutput
{
	double finalScore;
	double deltaScore;
	double f1Score;
	double fp, tp, fn, tn;
};

genann* g_pGenann = nullptr;
static const char* g_pNNFileNamePrefix = "classifier";

std::vector<std::filesystem::path> g_alertsPaths;
std::vector<std::filesystem::path> g_maliciousBehaviorPaths;

std::mutex g_coutMutex;

void TrainNetwork();
void Train();
AnalyzeOutput Analyze();
void SaveNeuralNetwork(const char* apPath, genann* apNetwork);

std::vector<TrainingSet> g_allSets;
std::vector<TrainingSet> g_trainingSets;
std::vector<TrainingSet> g_validationSets;

uint64_t g_totalEntries = 0;

int32_t g_hiddenLayers = 4;
int32_t g_hiddenLayerNeurons = (EInputs::SIZE + 1) / 2;
size_t g_maxGenerations = 1;
size_t g_maxIterations = 8;
double g_threshold = 0.5;
std::string g_saveFileName;

std::chrono::time_point g_startTime = std::chrono::high_resolution_clock::now();

int main(int32_t aArgC, char* apArgV[])
{
	// Init RNG
	srand(uint32_t(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

	std::filesystem::path logPath = std::filesystem::current_path() / ".." / ".." / "Experiments";

	if (aArgC > 1)
	{
		logPath = apArgV[1];

		if (aArgC > 2)
		{
			try {
				g_hiddenLayers = std::stoi(std::string(apArgV[2]));
			}
			catch (...) { std::cerr << "Arg 2 invalid! Expected int, got " << apArgV[2] << std::endl; }

			if (aArgC > 3)
			{
				try {
					g_hiddenLayerNeurons = std::stoi(std::string(apArgV[3]));
				}
				catch (...) { std::cerr << "Arg 3 invalid! Expected int, got " << apArgV[3] << std::endl; }

				if (aArgC > 4)
				{
					try {
						g_maxIterations = std::stoi(std::string(apArgV[4]));
					}
					catch (...) { std::cerr << "Arg 4 invalid! Expected int, got " << apArgV[4] << std::endl; }

					if (aArgC > 5)
					{
						try {
							g_threshold = std::stod(std::string(apArgV[5]));
						}
						catch (...) { std::cerr << "Arg 5 invalid! Expected double, got " << apArgV[5] << std::endl; }
					}
				}
			}
		}
	}

	// Initialize neural network
	g_saveFileName = g_pNNFileNamePrefix
		+ std::string("_") + std::to_string(g_hiddenLayers) + "hl"
		+ std::string("_") + std::to_string(g_hiddenLayerNeurons) + "hlnodes"
		+ std::string("_") + std::to_string(g_maxIterations) + "iters"
		+ std::string("_") + std::to_string(g_threshold) + "thold"
		+ ".nn"
		;

	g_pGenann = nullptr;
	FILE* pFile = fopen(g_saveFileName.c_str(), "r");
	if (pFile)
	{
		g_pGenann = genann_read(pFile);
		fclose(pFile);
		if (g_pGenann)
		{
			std::cout << "[INFO] Successfully loaded the dectetor network from disk!" << std::endl;
		}
	}
	if (!g_pGenann)
	{
		std::cout << "[INFO] Creating detector nn from scratch (" << g_hiddenLayers << " HLs, " << g_hiddenLayerNeurons << " HL Nodes)..." << std::endl;
		g_pGenann = genann_init(EInputs::SIZE, g_hiddenLayers, g_hiddenLayerNeurons, ETechniques::COUNT);
	}

	std::cout << "[INFO] Base log dir: " << logPath << std::endl;
	g_alertsPaths.push_back(std::filesystem::current_path() / "Alerts");
	//g_maliciousBehaviorPaths.push_back(logPath / "Additional (PAS and PVWA)");
	g_maliciousBehaviorPaths.push_back(logPath / "Techniques");

	Train();

	// ...

	std::chrono::time_point endTime = std::chrono::high_resolution_clock::now();

	auto timeElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - g_startTime).count();
	std::ofstream timeFile = std::ofstream(("time-elapsed_" + g_saveFileName + ".txt").c_str(), std::ios::out | std::ios::trunc);
	std::string timeElapsedStr = std::to_string(timeElapsed);
	timeFile.write(timeElapsedStr.c_str(), timeElapsedStr.size());

	return 0;
}

std::vector<std::filesystem::path> GetLogs(std::filesystem::path aRootDir, const std::string& acEndsWith)
{
	std::vector<std::filesystem::path> ret;

	// Recursively look for _sanitized.json files that we can parse
	for (auto& entry : std::filesystem::directory_iterator(aRootDir))
	{
		if (entry.is_regular_file())
		{
			std::string fileName = entry.path().filename().string();
			auto pos = fileName.find(acEndsWith);
			if (pos != std::string::npos)
			{
				ret.push_back(entry.path());
			}
		}
		else if (entry.is_directory())
		{
			std::vector<std::filesystem::path> ret2 = GetLogs(entry.path(), acEndsWith);
			for (const auto& ret2Entry : ret2)
			{
				ret.push_back(ret2Entry);
			}
		}
	}

	return ret;
}

void Train()
{
	g_fieldCounts.resize(EInputs::SIZE);

	std::vector<std::filesystem::path> logEntries;

	// Malicious behavior
	std::cout << "[INFO] Reading in known malicious behavior..." << std::endl;
	for (const auto& cPath : g_maliciousBehaviorPaths)
	{
		auto entries = GetLogs(cPath, "_sanitized_malicious.");
		for (auto& aEntry : entries)
		{
			logEntries.push_back(std::move(aEntry));
		}
	}

	// Build dictionary from this known behavior
	for (const auto& filePath : logEntries)
	{
		std::ifstream file(filePath.string(), std::ios::in | std::ios::binary);
		if (file.is_open())
		{
			file.ignore(std::numeric_limits<std::streamsize>::max());
			std::streamsize length = file.gcount();
			file.seekg(0, std::ios_base::beg);

			std::string fileBuffer;
			fileBuffer.resize(length);

			file.read(&fileBuffer[0], length);
			std::string error;
			json11::Json json = json11::Json::parse(fileBuffer, error);

			if (!error.empty())
			{
				std::cout << "[ERROR] Reading json file: " << error << " (file: " << filePath << ")" << std::endl;
				continue;
			}

			std::vector<double> outputs;
			outputs.push_back(0.0);
			for (auto entry : json.array_items())
			{
				AddDictionaryEntry(entry.dump(), false);
			}
		}
	}

	CalculateHighestTfIdf();

	// Parse to inputs
	for (const auto& filePath : logEntries)
	{
		std::ifstream file(filePath.string(), std::ios::in | std::ios::binary);
		if (file.is_open())
		{
			file.ignore(std::numeric_limits<std::streamsize>::max());
			std::streamsize length = file.gcount();
			file.seekg(0, std::ios_base::beg);

			std::string fileBuffer;
			fileBuffer.resize(length);

			file.read(&fileBuffer[0], length);
			std::string error;
			json11::Json json = json11::Json::parse(fileBuffer, error);

			if (!error.empty())
			{
				std::cout << "[ERROR] Reading json file: " << error << std::endl;
				continue;
			}

			std::vector<double> outputs;
			outputs.resize(ETechniques::COUNT);
			
			// Find technique that belongs with this dataset
			std::string fileName = filePath.filename().string();
			fileName.erase(fileName.begin());
			std::string numberStr;
			ETechniques id = ETechniques::COUNT;
			for (size_t i = 0; i < fileName.size(); ++i)
			{
				if (fileName[i] >= '0' && fileName[i] <= '9')
				{
					numberStr += fileName[i];
				}
				else
				{
					break;
				}
			}
			try
			{
				id = ETechniques(std::stoi(numberStr) - 1);
			}
			catch (...)
			{
				std::cout << "[ERROR] Failed to extract Technique ID: Failed converting string " << numberStr << " (from " << fileName << ") to int" << std::endl;
				continue;
			}
			if (id == ETechniques::COUNT)
			{
				std::cout << "[ERROR] Failed to extract Technique ID: Failed converting string " << numberStr << " (from " << fileName << ") to TechniqueID" << std::endl;
			}
			outputs[id] = 1.0;

			// Parse log entry
			const auto& cInputs = GetInputs(json.dump());
			if (cInputs.empty())
			{
				std::cout << "[WARNING] File " << filePath << " has no JSON entries" << std::endl;
				continue;
			}
			
			if (cInputs.size() < EInputs::SIZE)
			{
				for (auto entry : json.array_items())
				{
					g_totalEntries++;
					g_allSets.push_back(TrainingSet(GetInputs(entry.dump()), outputs, entry.dump(), filePath));
				}
			}
			else
			{
				g_totalEntries++;
				g_allSets.push_back(TrainingSet(GetInputs(json.dump()), outputs, json.dump(), filePath));
			}
		}
	}

	// Randomize training set order
	std::cout << "[INFO] Total entries: " << g_totalEntries << std::endl;
	std::shuffle(std::begin(g_allSets), std::end(g_allSets), std::default_random_engine());

	// Start training
	AnalyzeOutput resultVal;
	size_t model = UINT32_MAX;
	const size_t cValidationSetSize = size_t(double(g_allSets.size()) * 0.25);
	std::vector<AnalyzeOutput> resultValues;
	size_t iteration = 0;
	while (iteration < (g_maxIterations + 1))
	{
		size_t startID = model * cValidationSetSize;

		// Increase the model at every iteration
		model++;
		startID = model * cValidationSetSize;
		// Reset the training set order and reshuffle the training sets if the model >= total training set capacity
		if (startID >= g_allSets.size())
		{
			std::cout << "[INFO] Starting a new sliding window and shuffling the data set..." << std::endl;
			model = 0;
			startID = 0;

			if (!resultValues.empty())
			{
				AnalyzeOutput total;
				total.deltaScore = 0.0;
				total.f1Score = 0.0;
				total.finalScore = 0.0;
				total.fn = total.fp = total.tn = total.tp = 0;
				for (const auto& res : resultValues)
				{
					total.finalScore += res.finalScore;
					total.deltaScore += res.deltaScore;
					total.f1Score += res.f1Score;
					total.tp += res.tp;
					total.tn += res.tn;
					total.fp += res.fp;
					total.fn += res.fn;
				}

				total.deltaScore /= resultValues.size();
				total.f1Score /= resultValues.size();
				total.finalScore = (total.deltaScore + total.f1Score) / 2.0;
				total.tp /= resultValues.size();
				total.tn /= resultValues.size();
				total.fp /= resultValues.size();
				total.fn /= resultValues.size();

				std::filesystem::path resultsPath = std::filesystem::current_path() / ("results_" + g_saveFileName + ".txt");

				std::ofstream file(resultsPath.string().c_str(), std::ios::app | std::ios::binary);
				if (file.is_open())
				{
					std::string toWrite = std::to_string(iteration)
						+ ", " + std::to_string(total.finalScore)
						+ ", " + std::to_string(total.deltaScore)
						+ ", " + std::to_string(total.f1Score)
						+ ", " + std::to_string(total.tp)
						+ ", " + std::to_string(total.tn)
						+ ", " + std::to_string(total.fp)
						+ ", " + std::to_string(total.fn)
						+ "\n";
					file.write(toWrite.c_str(), toWrite.size());
					std::cout << "[INFO] Result: " << toWrite << std::endl;
					std::cout << "[INFO] Successfully appended this result to " << resultsPath << "!" << std::endl;
				}

				if (total.finalScore >= 0.99)
				{
					std::cout << "[INFO] Done training the network with a final score of " << total.finalScore << "!" << std::endl;
					break;
				}
				else
				{
					std::cout << "[INFO] More training required - average score from previous sliding window was " << total.finalScore << std::endl;
				}
			}

			// Randomize training data
			std::shuffle(std::begin(g_allSets), std::end(g_allSets), std::default_random_engine());
			iteration++;
		}

		std::cout << "[INFO] Reallocating training and validation sets..." << std::endl;
		g_trainingSets.clear();
		g_validationSets.clear();
		size_t maliciousCount = 0;
		size_t normalCount = 0;

		if (startID + cValidationSetSize < g_allSets.size())
		{
			for (size_t i = 0; i < g_allSets.size(); ++i)
			{
				if (i >= startID && i < (startID + cValidationSetSize))
				{
					g_validationSets.push_back(g_allSets[i]);
				}
				else
				{
					if (g_allSets[i].desiredOutputs[0] == 1.0)
					{
						maliciousCount++;
					}
					else
					{
						normalCount++;
					}
					g_trainingSets.push_back(g_allSets[i]);
				}
			}

			std::cout << "[INFO] Total training sets: " << g_allSets.size() << " | Training sets: " << g_trainingSets.size() << " | Validation sets: " << g_validationSets.size() << std::endl;
			std::cout << "[INFO] Malicious count: " << maliciousCount << " | Normal count: " << normalCount << std::endl;

			std::cout << "[INFO] Starting model " << model << " (validation range = " << (startID + 1) << "-" << ((model + 1) * cValidationSetSize) << ")" << std::endl;

			// Start training
			TrainNetwork();
			resultVal = Analyze();
			resultValues.push_back(resultVal);
		}
		else
		{
			std::cout << "[INFO] Not enough samples to provide a good training and validation set - skipping..." << std::endl;
		}
	}

	// Free memory
	genann_free(g_pGenann);
}

AnalyzeOutput Analyze()
{
	AnalyzeOutput ret;
	ret.deltaScore = 0.0;
	ret.f1Score = 0.0;
	ret.finalScore = 0.0;
	ret.fn = 0.0;
	ret.fp = 0.0;
	ret.tn = 0.0;
	ret.tp = 0.0;

	genann* pNetwork = g_pGenann;

	// Additional logging
	std::ofstream fnFile(std::filesystem::current_path() / "false_negatives.txt", std::ios::out | std::ios::trunc | std::ios::binary);
	std::ofstream fpFile(std::filesystem::current_path() / "false_positives.txt", std::ios::out | std::ios::trunc | std::ios::binary);
	std::ofstream tnFile(std::filesystem::current_path() / "true_negatives.txt", std::ios::out | std::ios::trunc | std::ios::binary);
	std::ofstream tpFile(std::filesystem::current_path() / "true_positives.txt", std::ios::out | std::ios::trunc | std::ios::binary);

	double totalError = 0.0;
	for (const auto& logEntry : g_trainingSets)
	{
		auto pOutputs = genann_run(pNetwork, &logEntry.inputs[0]);

		for (size_t o = 0; o < size_t(ETechniques::COUNT); ++o)
		{
			double maliciousRatio = pOutputs[o];
			if (maliciousRatio >= 0.5)
			{
				if (logEntry.desiredOutputs[o] < 0.5)
				{
					//std::cout << "[X] False positive " << maliciousRatio << std::endl;
					ret.fp += 1.0;
					totalError += maliciousRatio;

					std::string toWrite = logEntry.originalLog + "\n" + "\t" + logEntry.filePath.string() + "\n";
					fpFile.write(toWrite.c_str(), toWrite.size());

					continue;
				}

				//std::cout << "[O] Suspicious behavior detected (" << maliciousRatio << std::endl;// *100.0 << "% confidence)!" << std::endl;
				ret.tp += 1.0;
				totalError += 1.0 - maliciousRatio;

				std::string toWrite = logEntry.originalLog + "\n" + "\t" + logEntry.filePath.string() + "\n";
				tpFile.write(toWrite.c_str(), toWrite.size());

				// Uncomment if you want alerts
				/*std::string error;
				const json11::Json objectEntry = json11::Json::object({
					{ "confidence", maliciousRatio },
					{ "log", json11::Json::parse(logEntry.originalLog, error) }
					});
				auto nowTime = std::chrono::high_resolution_clock::now().time_since_epoch().count();
				std::ofstream outFile("Alerts/alert_" + std::to_string(nowTime) + ".json", std::ios::out | std::ios::binary);
				if (outFile.is_open())
				{
					const auto& str = objectEntry.dump();
					outFile.write(str.c_str(), str.size());
				}*/
			}
			else if (logEntry.desiredOutputs[o] >= 0.5)
			{
				//std::cout << "[X] Failed to detect malicious behavior! " << maliciousRatio << std::endl;// << "\t" << logEntry.originalLog << std::endl;
				ret.fn += 1.0;
				totalError += 1.0 - maliciousRatio;

				std::string toWrite = logEntry.originalLog + "\n" + "\t" + logEntry.filePath.string() + "\n";
				fnFile.write(toWrite.c_str(), toWrite.size());
			}
			else
			{
				//std::cout << "[O] Noice, filtered out normal behavior! " << maliciousRatio << std::endl;
				ret.tn += 1.0;
				totalError += maliciousRatio;

				std::string toWrite = logEntry.originalLog + "\n" + "\t" + logEntry.filePath.string() + "\n";
				tnFile.write(toWrite.c_str(), toWrite.size());
			}
		}
	}

	std::cout << "[INFO] Validation set parsing complete!" << std::endl;

	ret.deltaScore = 1.0 - (totalError / double(g_validationSets.size() * ETechniques::COUNT));

	// Calculate fitness
	double precision = 0.0;
	double recall = 0.0;
	ret.f1Score = 0.0;
	if (ret.tp > 0)
	{
		precision = double(ret.tp) / (double(ret.tp) + double(ret.fp));
		recall = double(ret.tp) / (double(ret.tp) + double(ret.fn));
		ret.f1Score = 2.0 * ((precision * recall) / (precision + recall));
	}

	ret.finalScore = (ret.deltaScore + ret.f1Score) / 2.0;

	std::cout << "[INFO] " << "Final score: " << ret.finalScore << " | Delta score: " << ret.deltaScore << " | F1 score: " << ret.f1Score << " | TP: " << ret.tp << " | TN: " << ret.fn << " | FP: " << ret.fp << " | FN: " << ret.fn << std::endl;

	// Write to file
	std::filesystem::path resultsPath = std::filesystem::current_path() / ("individual_" + g_saveFileName + ".txt");
	std::ofstream file(resultsPath.string().c_str(), std::ios::app | std::ios::binary);
	if (file.is_open())
	{
		std::string toWrite = std::to_string(ret.finalScore)
			+ ", " + std::to_string(ret.deltaScore)
			+ ", " + std::to_string(ret.f1Score)
			+ ", " + std::to_string(ret.tp)
			+ ", " + std::to_string(ret.tn)
			+ ", " + std::to_string(ret.fp)
			+ ", " + std::to_string(ret.fn)
			+ "\n";
		file.write(toWrite.c_str(), toWrite.size());
		std::cout << "[INFO] Individual result: " << toWrite << std::endl;
		std::cout << "[INFO] Successfully appended this individual result to " << resultsPath << "!" << std::endl;
	}

	return ret;
}

bool ResultIsCorrect(double aResult, double aDesired)
{
	if (aDesired < g_threshold)
	{
		if (aResult < g_threshold)
		{
			return true;
		}
	}
	else
	{
		if (aResult >= (1.0 - g_threshold))
		{
			return true;
		}
	}

	return false;
}

void Mutate(genann* apGenann, double aMutationPct = 100)
{
	int32_t weightsToAlter = 1 + rand() % 10;
	std::vector<int32_t> alteredWeightIDs;

	for (int32_t i = 0; i < weightsToAlter; ++i)
	{
		// Find a new random weight
		int32_t weightID = rand() % apGenann->total_weights;
		if (std::find(alteredWeightIDs.begin(), alteredWeightIDs.end(), weightID) != alteredWeightIDs.end())
		{
			i--;
			continue;
		}

		apGenann->weight[weightID] = -(double(rand()) / RAND_MAX) + (double(rand()) / RAND_MAX);
		alteredWeightIDs.push_back(weightID);
	}
}

void Breed(std::vector<genann*>& aPool, const std::vector<genann*>& acBreeders)
{
	for (size_t i = 0; i < aPool.size(); ++i)
	{
		// Don't mutate breeders
		if (std::find(acBreeders.begin(), acBreeders.end(), aPool[i]) != acBreeders.end())
		{
			continue;
		}

		// Copy over one of the breeders and mutate
		genann_free(aPool[i]);
		aPool[i] = genann_copy(acBreeders[rand() % acBreeders.size()]);
		Mutate(aPool[i], 100);
	}
}

void RunTest(std::vector<genann*>* apPool, std::vector<size_t>* apCorrects
	, std::vector<uint64_t>* apTruePositives, std::vector<uint64_t>* apTrueNegatives
	, std::vector<uint64_t>* apFalsePositives, std::vector<uint64_t>* apFalseNegatives
	, std::vector<double>* apTotalErrorDeltas
	, size_t aStart, size_t aEnd)
{
	for (size_t n = aStart; n < aEnd; ++n)
	{
		// Reset score
		(*apCorrects)[n] = 0;
		(*apTruePositives)[n] = 0;
		(*apTrueNegatives)[n] = 0;
		(*apFalsePositives)[n] = 0;
		(*apFalseNegatives)[n] = 0;
		(*apTotalErrorDeltas)[n] = 0.0;

		// Find correct results
		for (size_t i = 0; i < g_trainingSets.size(); ++i)
		{
			auto pOutputs = genann_run((*apPool)[n], &g_trainingSets[i].inputs[0]);

			for (size_t o = 0; o < size_t(ETechniques::COUNT); ++o)
			{
				double result = pOutputs[o];
				if (ResultIsCorrect(result, g_trainingSets[i].desiredOutputs[o]))
				{
					// Nice! - did we discover this as malicious (positive) or normal behavior (negative)?
					if (g_trainingSets[i].desiredOutputs[o] < 0.5)
					{
						(*apTrueNegatives)[n]++;
						(*apTotalErrorDeltas)[n] += result;
					}
					else
					{
						(*apTruePositives)[n]++;
						(*apTotalErrorDeltas)[n] += (1.0 - result);
					}
					(*apCorrects)[n]++;
				}
				else
				{
					// Uh - did we discover this as malicious (positive) or normal behavior (negative)?
					if (g_trainingSets[i].desiredOutputs[o] < 0.5)
					{
						(*apFalseNegatives)[n]++;
						(*apTotalErrorDeltas)[n] += result;
					}
					else
					{
						(*apFalsePositives)[n]++;
						(*apTotalErrorDeltas)[n] += (1.0 - result);
					}
				}
			}
		}
	}
}

void TrainNetwork()
{
	{
		std::unique_lock<std::mutex> _{ g_coutMutex };
		std::cout << "[INFO] Starting genetic neural network training..." << std::endl;
	}

	size_t threadCount = std::thread::hardware_concurrency();
#if _DEBUG
	threadCount = 1;
#endif

	static constexpr size_t s_cDesiredPoolSize = 512;
	const size_t poolSize = (s_cDesiredPoolSize / threadCount) * threadCount; // Ensure pool size is divisible by threadCount

	std::vector<std::thread> threads;
	threads.resize(threadCount);
	const size_t poolsizePerThread = poolSize / threadCount;

	{
		std::unique_lock<std::mutex> _{ g_coutMutex };
		std::cout << "[INFO] Thread count: " << threadCount << ". Pool size: " << poolSize << ". Pool size per thread: " << poolsizePerThread << std::endl;
	}

	static constexpr size_t s_cBreederSize = 16;
	std::vector<genann*> pool;
	std::vector<size_t> corrects;
	std::vector<size_t> truePositives;
	std::vector<size_t> trueNegatives;
	std::vector<size_t> falsePositives;
	std::vector<size_t> falseNegatives;
	std::vector<double> totalErrorDeltas;

	pool.resize(poolSize);
	corrects.resize(poolSize);
	truePositives.resize(poolSize);
	trueNegatives.resize(poolSize);
	falsePositives.resize(poolSize);
	falseNegatives.resize(poolSize);
	totalErrorDeltas.resize(poolSize);

	// Init pool
	pool[0] = genann_copy(g_pGenann);
	for (size_t i = 1; i < poolSize; ++i)
	{
		pool[i] = genann_copy(g_pGenann);
		Mutate(pool[i]);
	}

	// Start training
	double correctPct = 0.0;
	double highestPct = 0.0;

	double currentF1Score = 0.0;
	double highestF1Score = 0.0;

	double currentDeltaScore = 0.0;
	double highestDeltaScore = 0.0;

	double currentFinalScore = 0.0;
	double highestFinalScore = 0.0;

	size_t highestCorrects = 0;
	size_t generation = 0;

	{
		auto now = std::chrono::system_clock::now();
		std::time_t now_time = std::chrono::system_clock::to_time_t(now);
		std::unique_lock<std::mutex> _{ g_coutMutex };
		std::cout << "[INFO] Starting time: " << std::ctime(&now_time);
	}

	genann* pBestNetwork = nullptr;
	while (generation < g_maxGenerations)
	{
		// Start timer
		auto start = std::chrono::system_clock::now();

		// Run results
		for (size_t i = 0; i < threads.size(); ++i)
		{
			threads[i] = std::thread(&RunTest
				, &pool, &corrects
				, &truePositives, &trueNegatives, &falsePositives, &falseNegatives
				, &totalErrorDeltas
				, i * poolsizePerThread, (i + 1) * poolsizePerThread
			);
		}

		// Wait for threads to be done
		for (size_t i = 0; i < threads.size(); ++i)
		{
			threads[i].join();
		}

		// Collect breeders
		std::vector<genann*> breeders;
		std::vector<double> breederF1Scores;
		std::vector<double> breederDeltaScores;
		std::vector<double> breederFinalScores;
		std::vector<size_t> breederCorrects;
		breeders.resize(s_cBreederSize);
		breederCorrects.resize(s_cBreederSize);
		breederDeltaScores.resize(s_cBreederSize);
		breederF1Scores.resize(s_cBreederSize);
		breederFinalScores.resize(s_cBreederSize);

		double bestBreederScore = 0.0;
		size_t tp = 0, fp = 0, tn = 0, fn = 0;
		for (size_t n = 0; n < poolSize; ++n)
		{
			// Calculate fitness
			double precision = 0.0;
			double recall = 0.0;
			double f1Score = 0.0;
			if (truePositives[n] > 0)
			{
				precision = double(truePositives[n]) / (double(truePositives[n]) + double(falsePositives[n]));
				recall = double(truePositives[n]) / (double(truePositives[n]) + double(falseNegatives[n]));
				f1Score = 2.0 * ((precision * recall) / (precision + recall));
			}

			double deltaScore = 1.0 - (totalErrorDeltas[n] / (g_trainingSets.size() * ETechniques::COUNT));

			double finalScore = (f1Score + deltaScore) / 2.0;

			// Find replacement for breeder in case we outscored one
			for (size_t b = 0; b < s_cBreederSize; ++b)
			{
				// Better than this specific breeder?
				if (finalScore > breederFinalScores[b] || breeders[b] == nullptr)
				{
					breederDeltaScores[b] = deltaScore;
					breederF1Scores[b] = f1Score;
					breederFinalScores[b] = finalScore;
					breederCorrects[b] = corrects[n];
					breeders[b] = pool[n];

					// Highscore between these breeders?
					if (finalScore > bestBreederScore)
					{
						bestBreederScore = finalScore;
						pBestNetwork = pool[n];
						tp = truePositives[n];
						fp = falsePositives[n];
						tn = trueNegatives[n];
						fn = falseNegatives[n];
					}
					break;
				}
			}
		}

		// Breed
		Breed(pool, breeders);

		// Log best to worst %
		std::sort(breederFinalScores.begin(), breederFinalScores.end());
		std::reverse(breederFinalScores.begin(), breederFinalScores.end());

		// Stats and logging
		correctPct = 100.0 / double(g_trainingSets.size() * ETechniques::COUNT) * double(breederCorrects[0]);
		currentDeltaScore = breederDeltaScores[0];
		currentF1Score = breederF1Scores[0];
		currentFinalScore = breederFinalScores[0];

		// Highest ever score?
		if (currentFinalScore > highestFinalScore)
		{
			highestPct = correctPct;
			highestCorrects = breederCorrects[0];
			highestF1Score = currentF1Score;
			highestDeltaScore = currentDeltaScore;
			highestFinalScore = currentFinalScore;
			SaveNeuralNetwork(g_saveFileName.c_str(), pBestNetwork);
		}

		// Collect timestamp
		auto now = std::chrono::system_clock::now();
		std::time_t now_time = std::chrono::system_clock::to_time_t(now);
		std::chrono::duration<double> elapsed = now - start;

		// Print result
		{
			std::unique_lock<std::mutex> _{ g_coutMutex };
			// Print generation and stats
			std::cout << "[INFO] Generation " << generation << "\tFinal score: " << highestFinalScore << "\tDelta score: " << highestDeltaScore << "\tF1 Score: " << highestF1Score << "\tCorrect: " << highestPct << "% (" << highestCorrects << "/" << (g_trainingSets.size() * ETechniques::COUNT) << ", TP: " << tp << " FP: " << fp << " TN: " << tn << " FN: " << fn << ")\tElapsed: " << elapsed.count() << "s\tTimestamp: " << std::ctime(&now_time);
		}

		generation++;
	}

	g_pGenann = pBestNetwork;

	for (size_t i = 0; i < poolSize; ++i)
	{
		if (pool[i] != pBestNetwork)
		{
			genann_free(pool[i]);
		}
	}
}

void SaveNeuralNetwork(const char* apPath, genann* apNetwork)
{
	// Save NN
	FILE* pFile = fopen(apPath, "w");
	if (pFile)
	{
		genann_write(apNetwork, pFile);
		fclose(pFile);

		{
			std::unique_lock<std::mutex> _{ g_coutMutex };
			std::cout << "[INFO] Successfully saved the neural network to " << std::filesystem::current_path() / apPath << "!" << std::endl;
		}
	}
	else
	{
		std::unique_lock<std::mutex> _{ g_coutMutex };
		std::cout << "[ERROR] Failed to save neural network!" << std::endl;
	}
}