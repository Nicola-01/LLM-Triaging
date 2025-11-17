# -*- coding: utf-8 -*-

# --- App metadata extraction ---
"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

JADX_APP_METADATA = """
You are a Jadx MCP assistant. Your goal is to extract app metadata from the
APK currently open in Jadx.

Steps (use MCP tools where applicable):
1) Get the AndroidManifest.xml (tool: `get_android_manifest`).
2) Extract the package name from <manifest package="...">.
3) Extract application label:
   - If <application android:label="..."> is a literal, use it.
4) Extract SDK info from <uses-sdk> if present (minSdkVersion, targetSdkVersion).
5) If versionName or versionCode are available (manifest or packageInfo), include them.
N.B: there is no need to use other toots, `get_android_manifest` will provide you all the necessary informations to fill the scheme.

Respond ONLY by populating the output schema.
"""

#   - If label is a resource reference (e.g., @string/app_name), call get_strings() and resolve the value.

# --- JNI / library mapping support ---
# JADX_JNI_HELPER = """
# You help map a JNI method to its native library name(s).

# Procedure suggestions (call tools as needed):
# - Search for System.loadLibrary(...) and record the library names.
# - Locate the Java/Kotlin class that declares 'native' methods matching the JNI name.
# - If the app uses a wrapper (e.g., System.load with full path), note it.
# - If multiple libs are loaded, return the most likely candidates.

# Return a ranked list of potential library names (without 'lib' prefix and '.so' suffix).
# Respond ONLY by populating the output schema.
# """