import os
import plistlib
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "macos" / "workflows"
TEMPLATE_DOC = Path("/System/Library/Services/Show Map.workflow/Contents/Resources/document.wflow")
TEMPLATE_INFO = Path("/System/Library/Services/Encode Selected Video Files.workflow/Contents/Info.plist")
TEMPLATE_VERSION = Path("/System/Library/Services/Encode Selected Video Files.workflow/Contents/version.plist")

WORKFLOWS = [
    {
        "bundle": "Upload to Transfer (3 days).workflow",
        "name": "Upload to Transfer (3 days)",
        "identifier": "local.tfworks.transfer.upload3days",
        "menu": "上传到 transfer（3天）",
        "command": 'for f in "$@"; do "$HOME/bin/transfer-upload" "$f"; done',
    },
    {
        "bundle": "Upload to Transfer (Forever).workflow",
        "name": "Upload to Transfer (Forever)",
        "identifier": "local.tfworks.transfer.uploadforever",
        "menu": "上传到 transfer（长期）",
        "command": 'for f in "$@"; do "$HOME/bin/transfer-upload" --long-term "$f"; done',
    },
]


def build(spec):
    bundle = OUT / spec["bundle"]
    if bundle.exists():
        shutil.rmtree(bundle)
    contents = bundle / "Contents"
    resources = contents / "Resources"
    resources.mkdir(parents=True, exist_ok=True)

    info = plistlib.load(TEMPLATE_INFO.open("rb"))
    info["CFBundleIdentifier"] = spec["identifier"]
    info["CFBundleName"] = spec["name"]
    info["NSServices"] = [{
        "NSMenuItem": {"default": spec["menu"]},
        "NSMessage": "runWorkflowAsService",
        "NSRequiredContext": {"NSApplicationIdentifier": "com.apple.finder"},
        "NSSendFileTypes": ["public.item"],
    }]
    with (contents / "Info.plist").open("wb") as f:
        plistlib.dump(info, f, fmt=plistlib.FMT_XML)

    version = plistlib.load(TEMPLATE_VERSION.open("rb"))
    with (contents / "version.plist").open("wb") as f:
        plistlib.dump(version, f, fmt=plistlib.FMT_XML)

    doc = plistlib.load(TEMPLATE_DOC.open("rb"))
    doc["workflowMetaData"] = {
        "serviceApplicationBundleID": "com.apple.finder",
        "serviceApplicationPath": "/System/Library/CoreServices/Finder.app",
        "serviceInputTypeIdentifier": "com.apple.Automator.fileSystemObject",
        "serviceOutputTypeIdentifier": "com.apple.Automator.nothing",
        "serviceProcessesInput": 0,
        "workflowTypeIdentifier": "com.apple.Automator.servicesMenu",
    }
    action = doc["actions"][0]["action"]
    action["ActionParameters"] = {
        "COMMAND_STRING": spec["command"],
        "CheckedForUserDefaultShell": True,
        "inputMethod": 1,
        "shell": "/bin/zsh",
        "source": "",
    }
    action["AMAccepts"] = {
        "Container": "List",
        "Optional": True,
        "Types": ["com.apple.cocoa.string"],
    }
    action["AMProvides"] = {
        "Container": "List",
        "Types": ["com.apple.cocoa.string"],
    }
    with (resources / "document.wflow").open("wb") as f:
        plistlib.dump(doc, f, fmt=plistlib.FMT_XML)

    print("built", bundle)


for item in WORKFLOWS:
    build(item)
