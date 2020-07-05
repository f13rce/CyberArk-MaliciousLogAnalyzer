#pragma once

enum ETechniques
{
	// Techniques
	Phishing,
	CommandLineInterface,
	UserExecution,
	CreateAccount,
	FileAndDirectoryPermissionsModification,
	IndicatorRemovalOnHost,
	ModifyRegistry,
	ArchiveCollectedData,
	DataFromLocalSystem,
	DataFromNetworkSharedDrive,
	DataFromRemovableMedia,
	BootOrLogonInitializationScripts,
	AbuseElevationControlMechanism,
	ImpairDefenses,
	InputCapture,
	StealWebSessionCookie,
	DataEncryptedForImpact,

	// Additionals
	/*SuspiciousPasswordHarvestingInPVWA,
	CircumventingPSM,
	CaptureClientSessionCookies,
	DeactivatingSecurityConfiguration,
	TemperingWithStoredDataInVault,
	SuspiciousPasswordHarvestingInVault,
	AddingUserManuallyToCyberArk,
	ChangeUserManuallyInCyberArk,
	ShuttingDownVault*/

	COUNT
};