#!/usr/bin/env bash

# iosramdisk.sh: A script to create and boot iOS Ramdisks.
# Author: [Your Name/Organization]
# Version: 0.1.0

# --- Global Variables ---
SCRIPT_VERSION="0.1.0"
WORK_DIR_BASE="work_iosramdisk"
OUTPUT_DIR="created_ramdisks"
TOOLS_PATH="" # To be set by check_os
OS_TYPE=""    # To be set by check_os (Darwin or Linux)
CURRENT_TASK_WORK_DIR="" # To be set by setup_workspace

# Firmware component information
IPSW_URL=""
MANIFEST_BUILD_IDENTITY_PATH="BuildIdentities[0].Manifest" # Default path, might need adjustment
MANIFEST_IBSS_PATH=""
MANIFEST_IBEC_PATH=""
MANIFEST_KERNELCACHE_PATH=""
MANIFEST_DEVICETREE_PATH=""
MANIFEST_RAMDISK_PATH=""
MANIFEST_TRUSTCACHE_PATH="" # Optional

# Local paths to downloaded components
LOCAL_BUILDMANIFEST_PATH=""
LOCAL_IBSS_PATH=""
LOCAL_IBEC_PATH=""
LOCAL_KERNELCACHE_PATH=""
LOCAL_DEVICETREE_PATH=""
LOCAL_RAMDISK_PATH=""
LOCAL_TRUSTCACHE_PATH="" # Optional

# Device State
DEVICE_CPID=""
DEVICE_ECID=""
DEVICE_PWND_STATE="NO" # NO, YES

# SHSH and Signing
SHSH_BLOB_PATH="" # Path to the .shsh blob for the device
IM4M_PATH=""      # Path to the extracted IM4M from SHSH

# Processed components
FINAL_IBSS_IMG4_PATH=""
FINAL_IBEC_IMG4_PATH=""
FINAL_KERNELCACHE_IMG4_PATH=""
FINAL_DEVICETREE_IMG4_PATH=""
FINAL_TRUSTCACHE_IMG4_PATH="" # Might remain empty if not applicable
FINAL_RAMDISK_IMG4_PATH=""
FINAL_BOOTLOGO_IMG4_PATH="" # Optional

# Device Info (expanded)
DEVICE_MODEL_RAW="" # e.g. J274ap, D22ap - from irecovery
IOS_MAJOR_VERSION="" # e.g. 15, 16 - from user input

# --- Achilles-like Options (parsed globally) ---
# Stores the device UDID if specified with -u
OPT_DEVICE_UDID=""
# Stores custom boot arguments if specified with -b
OPT_BOOT_ARGS=""
# Stores path to custom iBSS/PongoOS if specified with -k
# (Recommended location for auto-suggestion: boot_files/pongo/PongoOS_<CPID>.bin)
OPT_CUSTOM_IBSS_PATH=""
# Stores path to custom KernelCache/KPF if specified with -K
# (Recommended location for auto-suggestion: boot_files/kpf/kpf_<CPID>.img4 or kernelcache_<CPID>.img4)
OPT_CUSTOM_KERNEL_PATH=""
# Stores path to custom Ramdisk.dmg if specified with -R
# (Recommended location for auto-suggestion: boot_files/ramdisks/)
OPT_CUSTOM_RAMDISK_PATH=""
# Stores path to custom Overlay.dmg if specified with -O (currently informational)
# (Recommended location for auto-suggestion: boot_files/overlays/)
OPT_CUSTOM_OVERLAY_PATH=""
OPT_A9_ALT_FILES="false" # For A9 devices, determines if alternative (e.g., s8003) files/keys should be used

# IVs and Keys for components (to be fetched from Apple Wiki)
DEVICE_IBSS_IV=""
DEVICE_IBSS_KEY=""
DEVICE_IBEC_IV=""
DEVICE_IBEC_KEY=""


# --- Logging Functions ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S'): $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S'): $1" >&2
    exit 1
}

log_debug() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        echo "[DEBUG] $(date +'%Y-%m-%d %H:%M:%S'): $1"
    fi
}

# --- OS Check ---
check_os() {
    log_debug "Checking OS type..."
    case "$(uname -s)" in
        Darwin)
            OS_TYPE="Darwin"
            TOOLS_PATH="tools/macos"
            log_info "Detected OS: Darwin"
            ;;
        Linux)
            OS_TYPE="Linux"
            TOOLS_PATH="tools/linux"
            log_info "Detected OS: Linux"
            ;;
        *)
            log_error "Unsupported OS: $(uname -s). This script supports Darwin (macOS) and Linux only."
            ;;
    esac
    if [[ ! -d "$TOOLS_PATH" ]]; then
        log_debug "Tools path '$TOOLS_PATH' does not exist. Attempting to create it."
        mkdir -p "$TOOLS_PATH"
        if [[ $? -ne 0 ]]; then
            log_error "Failed to create tools directory: $TOOLS_PATH"
        fi
        log_info "Created tools directory: $TOOLS_PATH. Please place required tools here."
    fi
}

# --- Required Tools ---
REQUIRED_TOOLS=(
    "gaster"
    "irecovery"
    "img4"
    "img4tool"
    "iBoot64Patcher"
    "KPlooshFinder"
    "kerneldiff"
    "pzb"
    "jq"
    "curl"
    "sshpass"
    "iproxy"
    # hfsplus is Linux only, hdiutil is macOS only. gtar for macOS.
)

# --- Tool Check ---
check_tools() {
    log_info "Checking for required tools..."

    local os_specific_tools=()
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        os_specific_tools+=("hdiutil" "PlistBuddy" "gtar") # PlistBuddy is usually /usr/libexec/PlistBuddy
    elif [[ "$OS_TYPE" == "Linux" ]]; then
        os_specific_tools+=("hfsplus" "PlistBuddy") # PlistBuddy needs to be installed on Linux
    fi

    local current_required_tools=("${REQUIRED_TOOLS[@]}" "${os_specific_tools[@]}")
    local all_tools_found=true

    for tool_filename in "${current_required_tools[@]}"; do
        local tool_path="$TOOLS_PATH/$tool_filename"
        local tool_name_upper # Variable to store the uppercase tool name for global var, e.g., GASTER_BIN

        # Handle tools that might be system-wide vs in TOOLS_PATH
        if [[ "$tool_filename" == "hdiutil" && "$OS_TYPE" == "Darwin" ]]; then
            if ! command -v hdiutil &> /dev/null; then
                log_error "Required tool 'hdiutil' not found in PATH for Darwin."
                all_tools_found=false
                continue
            fi
            tool_path=$(command -v hdiutil)
        elif [[ "$tool_filename" == "gtar" && "$OS_TYPE" == "Darwin" ]]; then
            # gtar might be installed via Homebrew (e.g. /usr/local/bin/gtar or /opt/homebrew/bin/gtar) or be in TOOLS_PATH
            if [[ -x "$TOOLS_PATH/gtar" ]]; then
                 tool_path="$TOOLS_PATH/gtar"
            elif command -v gtar &> /dev/null; then
                tool_path=$(command -v gtar)
                log_debug "Found 'gtar' in system PATH: $tool_path"
            else
                log_error "Required tool 'gtar' not found in '$TOOLS_PATH/gtar' or in system PATH for Darwin."
                all_tools_found=false
                continue
            fi
        elif [[ "$tool_filename" == "PlistBuddy" && "$OS_TYPE" == "Darwin" ]]; then
             # On macOS, PlistBuddy is often at /usr/libexec/PlistBuddy
            if [[ -x "/usr/libexec/PlistBuddy" ]]; then
                tool_path="/usr/libexec/PlistBuddy"
            elif ! command -v PlistBuddy &> /dev/null; then # Check PATH if not in default location
                 log_error "Required tool 'PlistBuddy' not found at /usr/libexec/PlistBuddy or in PATH for Darwin."
                 all_tools_found=false
                 continue
            else
                tool_path=$(command -v PlistBuddy)
            fi
        elif [[ "$tool_filename" == "hfsplus" && "$OS_TYPE" == "Linux" ]]; then
            if [[ -x "$TOOLS_PATH/hfsplus" ]]; then # Prioritize tools in TOOLS_PATH
                tool_path="$TOOLS_PATH/hfsplus"
            elif command -v hfsplus-tools &> /dev/null; then # Check for hfsplus-tools (common package name)
                # The actual binary might just be 'hfsplus' or part of a suite.
                # This check is a bit indirect. If hfsplus-tools installs 'hfsplus' in PATH, next check handles it.
                # For now, we assume if 'hfsplus-tools' command exists, 'hfsplus' binary might too.
                # A more direct check for the 'hfsplus' binary itself is preferred.
                 if command -v hfsplus &> /dev/null; then
                    tool_path=$(command -v hfsplus)
                    log_debug "Found 'hfsplus' (likely from hfsplus-tools) in system PATH: $tool_path"
                 else
                    log_warn "Found 'hfsplus-tools' but 'hfsplus' command not directly in PATH. Ensure it's in $TOOLS_PATH."
                    # The generic check below will try $TOOLS_PATH/hfsplus
                 fi
            fi
            # Fall through to the generic -x "$tool_path" check
        fi

        # Generic check for tools expected in $TOOLS_PATH or system PATH
        if [[ ! -x "$tool_path" ]]; then
             if command -v "$tool_filename" &> /dev/null; then # Check system PATH if not found or not exec in $TOOLS_PATH
                tool_path=$(command -v "$tool_filename")
                log_debug "Tool '$tool_filename' found in system PATH: $tool_path"
            else
                log_error "Required tool '$tool_filename' not found or not executable at '$TOOLS_PATH/$tool_filename'. Also not found in system PATH."
                all_tools_found=false
                continue
            fi
        fi

        tool_name_upper=$(echo "$tool_filename" | tr '[:lower:]' '[:upper:]' | sed 's/-/_/g')
        declare -g "${tool_name_upper}_BIN"="$tool_path"
    for tool_filename in "${REQUIRED_TOOLS[@]}"; do
        local tool_path="$TOOLS_PATH/$tool_filename"
        local tool_name_upper # Variable to store the uppercase tool name for global var, e.g., GASTER_BIN

        # Handle tools that might be system-wide vs in TOOLS_PATH
        if [[ "$tool_filename" == "hdiutil" && "$OS_TYPE" == "Darwin" ]]; then
            if ! command -v hdiutil &> /dev/null; then
                log_error "Required tool 'hdiutil' not found in PATH for Darwin."
                all_tools_found=false
                continue
            fi
            tool_path=$(command -v hdiutil)
        elif [[ "$tool_filename" == "PlistBuddy" && "$OS_TYPE" == "Darwin" ]]; then
             # On macOS, PlistBuddy is often at /usr/libexec/PlistBuddy
            if [[ -x "/usr/libexec/PlistBuddy" ]]; then
                tool_path="/usr/libexec/PlistBuddy"
            elif ! command -v PlistBuddy &> /dev/null; then # Check PATH if not in default location
                 log_error "Required tool 'PlistBuddy' not found at /usr/libexec/PlistBuddy or in PATH for Darwin."
                 all_tools_found=false
                 continue
            else
                tool_path=$(command -v PlistBuddy)
            fi
        elif [[ ! -x "$tool_path" ]]; then
             # For other tools, check TOOLS_PATH first, then system PATH
            if command -v "$tool_filename" &> /dev/null; then
                tool_path=$(command -v "$tool_filename")
                log_debug "Tool '$tool_filename' found in system PATH: $tool_path"
            else
                log_error "Required tool '$tool_filename' not found or not executable at '$tool_path'. Also not found in system PATH."
                all_tools_found=false
                continue
            fi
        fi

        tool_name_upper=$(echo "$tool_filename" | tr '[:lower:]' '[:upper:]' | sed 's/-/_/g')
        declare -g "${tool_name_upper}_BIN"="$tool_path"
        log_debug "Tool $tool_filename found: ${!tool_name_upper}"
    done

    if [[ "$all_tools_found" == "false" ]]; then
        log_error "One or more required tools are missing. Please install them or place them in '$TOOLS_PATH'."
    else
        log_info "All required tools found."
    fi
}

# --- Workspace Setup ---
setup_workspace() {
    local task_name="$1"
    if [[ -z "$task_name" ]]; then
        log_error "Task name not provided for workspace setup."
    fi

    log_debug "Setting up workspace for task: $task_name"

    if [[ ! -d "$WORK_DIR_BASE" ]]; then
        log_info "Creating base work directory: $WORK_DIR_BASE"
        mkdir -p "$WORK_DIR_BASE" || log_error "Failed to create $WORK_DIR_BASE"
    fi

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log_info "Creating output directory: $OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR" || log_error "Failed to create $OUTPUT_DIR"
    fi

    local timestamp=$(date +%Y%m%d_%H%M%S)
    CURRENT_TASK_WORK_DIR="${WORK_DIR_BASE}/${task_name}_${timestamp}"

    if [[ -d "$CURRENT_TASK_WORK_DIR" ]]; then
        log_info "Cleaning up existing task work directory: $CURRENT_TASK_WORK_DIR"
        rm -rf "$CURRENT_TASK_WORK_DIR" || log_error "Failed to remove $CURRENT_TASK_WORK_DIR"
    fi

    log_info "Creating new task work directory: $CURRENT_TASK_WORK_DIR"
    mkdir -p "$CURRENT_TASK_WORK_DIR" || log_error "Failed to create $CURRENT_TASK_WORK_DIR"
    log_debug "Current task work directory set to: $CURRENT_TASK_WORK_DIR"
}

# --- Workspace Cleanup ---
cleanup_workspace() {
    log_debug "Running cleanup_workspace..."
    if [[ -n "$CURRENT_TASK_WORK_DIR" && -d "$CURRENT_TASK_WORK_DIR" ]]; then
        log_info "Cleaning up task work directory: $CURRENT_TASK_WORK_DIR"
        rm -rf "$CURRENT_TASK_WORK_DIR"
        if [[ $? -eq 0 ]]; then
            log_debug "Successfully removed $CURRENT_TASK_WORK_DIR"
        else
            # Log error but don't exit script as trap might be running on exit already
            echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S'): Failed to remove $CURRENT_TASK_WORK_DIR during cleanup." >&2
        fi
    else
        log_debug "No current task work directory to clean or it does not exist: $CURRENT_TASK_WORK_DIR"
    fi
}

# Trap for cleanup on exit
trap cleanup_workspace EXIT ERR INT TERM

# --- Display DFU Command Examples ---
# Prints a list of common command examples when a DFU device is detected
# and the script is run without a specific command.
# Attempts to find device-specific files to make examples more relevant.
display_dfu_command_examples() {
    local executable_name="${0##*/}"
    if [[ "$0" == */* ]]; then
        executable_name="$0"
    fi

    echo
    echo "----------------------------------------------------------------------"
    echo "DFU Device Detected! Generating command examples..."
    echo "----------------------------------------------------------------------"

    # Let's try a single irecovery -q call here to get info for suggestions.
    log_info "Fetching current DFU device information for command suggestions..."
    local local_dfu_info_output
    local local_cpid=""
    local local_ecid=""
    local local_model=""

    # Use existing $IRECOVERY_BIN
    if [[ -n "$IRECOVERY_BIN" && -x "$IRECOVERY_BIN" ]]; then
        local_dfu_info_output=$($IRECOVERY_BIN -q 2>&1)
        local irec_exit_code=$?
        if [[ $irec_exit_code -eq 0 ]]; then
            local mode=$(echo "$local_dfu_info_output" | grep -o 'MODE: [^ ]*' | awk '{print $2}')
            if [[ "$mode" == "DFU" ]]; then
                local_cpid=$(echo "$local_dfu_info_output" | grep 'CPID:' | awk '{print $2}' | cut -d',' -f1)
                local_ecid=$(echo "$local_dfu_info_output" | grep 'ECID:' | awk '{print $2}' | cut -d',' -f1) # Assuming ECID is hex
                local_model=$(echo "$local_dfu_info_output" | grep 'MODEL:' | awk '{print $2}' | cut -d',' -f1)
                log_info "Detected for suggestions: CPID: ${local_cpid:-N/A}, ECID: ${local_ecid:-N/A}, MODEL: ${local_model:-N/A}"
            else
                log_warn "Device not in DFU mode according to irecovery -q. Cannot generate specific suggestions."
            fi
        else
            log_warn "irecovery -q failed. Cannot get device info for specific suggestions."
        fi
    else
        log_warn "IRECOVERY_BIN not found or not executable. Cannot get device info for specific suggestions."
    fi

    echo
    echo "Tip: Organize your files using these conventions for easier use and future auto-detection:"
    echo "  SHSH Blobs: other/shsh/<ECID>.shsh or other/shsh/<CPID>.shsh"
    echo "  PongoOS (-k): boot_files/pongo/PongoOS_<CPID>.bin"
    echo "  KPF/Kernel (-K): boot_files/kpf/kpf_<CPID>.img4"
    echo "  Ramdisks (-R): boot_files/ramdisks/ (e.g., rootedramdisk.dmg)"
    echo

    # Example 1: Boot PongoOS
    local pongo_path_suggestion="./boot_files/pongo/PongoOS_${local_cpid:-<CPID>}.bin"
    if [[ -n "$local_cpid" && -f "boot_files/pongo/PongoOS_${local_cpid}.bin" ]]; then
        pongo_path_suggestion="boot_files/pongo/PongoOS_${local_cpid}.bin" # Use relative if found
        echo "[Found specific PongoOS: $pongo_path_suggestion]"
    fi
    echo "1. Boot a custom PongoOS (replaces iBSS/iBEC):"
    echo "   $executable_name boot -k $pongo_path_suggestion"
    echo

    # Example 2: Boot with KPF and a standard Ramdisk (from created set)
    local kpf_path_suggestion="./boot_files/kpf/kpf_${local_cpid:-<CPID>}.img4"
    if [[ -n "$local_cpid" && -f "boot_files/kpf/kpf_${local_cpid}.img4" ]]; then
        kpf_path_suggestion="boot_files/kpf/kpf_${local_cpid}.img4"
        echo "[Found specific KPF: $kpf_path_suggestion]"
    fi
    echo "2. Boot with a KPF (and a standard Ramdisk from a 'create' operation):"
    echo "   (Replace 'path/to/created_ramdisk_dir' with actual path from '$OUTPUT_DIR')"
    echo "   $executable_name boot path/to/created_ramdisk_dir -K $kpf_path_suggestion"
    echo

    # Example 3: Boot a custom Ramdisk (like rootedramdisk.dmg)
    local custom_ramdisk_path="./boot_files/ramdisks/rootedramdisk.dmg"
    local suggested_ramdisk_option="-R $custom_ramdisk_path"
    if [[ -f "$custom_ramdisk_path" ]]; then
        echo "[Found common ramdisk: $custom_ramdisk_path]"
    else
        suggested_ramdisk_option="-R ./boot_files/ramdisks/<your_ramdisk.dmg>"
    fi
    echo "3. Boot a custom Ramdisk (e.g., rootedramdisk.dmg):"
    echo "   (May also need a KPF: -K $kpf_path_suggestion)"
    echo "   $executable_name boot $suggested_ramdisk_option"
    echo

    # Example 4: Full custom boot set
    echo "4. Boot a fully custom set (PongoOS, KPF, Ramdisk):"
    echo "   $executable_name boot -k $pongo_path_suggestion -K $kpf_path_suggestion $suggested_ramdisk_option"
    echo

    echo "5. Boot with specific boot arguments (for PongoOS or custom iBEC):"
    echo "   $executable_name boot -k $pongo_path_suggestion -b \"your_boot_args_here\""
    echo

    # SHSH blob suggestion (informational, as SHSH is used in 'create')
    if [[ -n "$local_ecid" && -f "other/shsh/${local_ecid}.shsh" ]]; then
        echo "[Found SHSH for current device (by ECID): other/shsh/${local_ecid}.shsh]"
    elif [[ -n "$local_cpid" && -f "other/shsh/${local_cpid}.shsh" ]]; then
        echo "[Found SHSH for current device (by CPID): other/shsh/${local_cpid}.shsh]"
    else
        if [[ -n "$local_ecid" || -n "$local_cpid" ]]; then
            echo "[SHSH hint: Place SHSH for this device at 'other/shsh/${local_ecid:-<ECID>}.shsh' or 'other/shsh/${local_cpid:-<CPID>}.shsh']"
        fi
    fi
    echo
    echo "Remember to replace placeholders if specific files were not found."
    echo "The above examples use the new -k, -K, -R, -b options for booting."
    echo "----------------------------------------------------------------------"
    echo
}

# --- Usage Information ---
usage() {
    echo "iosramdisk.sh - Create and boot iOS Ramdisks"
    echo "Version: $SCRIPT_VERSION"
    echo ""
    echo "Usage: $0 [global_options] <command> [command_options]"
    echo ""
    echo "Global Options (can be placed before the command):"
    echo "  --debug             Enable debug logging."
    echo "  -u <UDID>           Specify a device UDID (Note: underlying tool support may vary)."
    echo "  -b <arguments>      Specify boot arguments (e.g., for iBEC or PongoOS; typically used with -k or custom bootloaders)."
    echo "  -k <file_path>      Path to a custom iBSS/PongoOS file to boot."
    echo "  -K <file_path>      Path to a custom KernelCache/KPF file to boot."
    echo "  -R <file_path>      Path to a custom Ramdisk.dmg file to boot."
    echo "  -O <file_path>      Path to a custom Overlay.dmg (Note: overlay processing is not yet implemented)."
    echo ""
    echo "Commands:"
    echo "  create      Create a new ramdisk."
    echo "    --ipsw <path_to_ipsw>       Path to the IPSW file (required)."
    echo "    --device <identifier>       Device identifier (e.g., iPhone10,3) (required)."
    echo "    --version <ios_version>     iOS version for the ramdisk (e.g., 15.1) (required)."
    echo "    --a9-alt                    Use alternative A9 chip variant files (e.g., for S8003 on iPhone 6s/SE). Affects IV/Key lookup and potentially file path selection if manifests differ."
    echo "    --key <boot_key>            Decryption key for the main DMG (optional)."
    echo "    --variant <variant_name>    Build variant (e.g., Install) (optional, defaults to Install)."
    echo "    --ipsw-url <url>            Direct URL to IPSW file (optional, overrides ipsw.me lookup)."
    echo ""
    echo "  boot [ramdisk_directory_path]"
    echo "              Boot a ramdisk. Uses components from [ramdisk_directory_path] unless overridden by -k, -K, -R."
    echo "              If [ramdisk_directory_path] is omitted, attempts to boot the latest"
    echo "              ramdisk found in '$OUTPUT_DIR'."
    echo "              Can be combined with global options like -k, -K, -R, -b."
    echo ""
    echo "  ssh         Connect to the iOS device via SSH (assumes ramdisk is booted"
    echo "              and SSHRD tools are on it, uses default alpine password)."
    echo ""
    echo "  clean       Remove all created ramdisks from the output directory ('$OUTPUT_DIR')."
    echo ""
    echo "  help, --help Show this help message."
    echo "  --version   Show script version."
    echo ""
    echo "Automatic DFU Detection:"
    echo "  If no command is specified and a DFU mode device is detected, the script will display"
    echo "  a list of common command examples to help you get started."
    echo ""
    echo "File Naming Conventions for Dynamic Suggestions (used with -k, -K, etc.):"
    echo "  The script can provide more relevant command examples if you follow these conventions:"
    echo "  - SHSH Blobs: place in 'other/shsh/'"
    echo "      - Preferred: <ECID>.shsh (e.g., 0x123456789ABCD.shsh)"
    echo "      - Fallback:  <CPID>.shsh (e.g., 0x8010.shsh)"
    echo "  - PongoOS (-k): place in 'boot_files/pongo/'"
    echo "      - Naming: PongoOS_<CPID>.bin (e.g., PongoOS_0x8010.bin)"
    echo "  - KPF/Custom Kernel (-K): place in 'boot_files/kpf/'"
    echo "      - Naming: kpf_<CPID>.img4 or kernelcache_<CPID>.img4"
    echo "  - Custom Ramdisks (-R): place in 'boot_files/ramdisks/'"
    echo "      - Naming: e.g., rootedramdisk.dmg, custom_ramdisk.dmg"
    echo "  - Custom Overlays (-O): place in 'boot_files/overlays/' (feature is conceptual)"
    echo "      - Naming: e.g., my_overlay.tar.gz"
    echo ""
    echo "Examples:"
    echo "  $0 create --ipsw path/to/firmware.ipsw --device iPhone10,3 --version 15.1"
    echo "  $0 boot created_ramdisks/iPhone10,3_15.1_.../"
    echo "  $0 -k customPongo.bin -R customRamdisk.dmg boot"
    echo "  $0 -b \"-v\" boot latest_ramdisk_dir/"
    echo ""
    echo "Required tools will be searched in '$TOOLS_PATH' (for your OS) or system PATH."
}

# --- Main Script Logic ---
main() {
    # Default DEBUG_MODE to false
    DEBUG_MODE="false"
    local main_command=""
    local command_args=() # Store arguments for the main command here

    # Pre-parse global options like --debug and command identifiers like help, --help, --version
    # This loop separates global options and the main command from command-specific arguments.
    local pre_parse_args=("$@") # Copy initial arguments
    local remaining_pre_parse_args=() # Arguments not consumed by this initial parse

    while [[ ${#pre_parse_args[@]} -gt 0 ]]; do
        local arg="${pre_parse_args[0]}"
        case "$arg" in
            --debug)
                DEBUG_MODE="true"
                # log_debug is not available until after this loop, so we'll log it later if needed.
                shift_array pre_parse_args 1
                ;;
            help|--help)
                usage
                exit 0
                ;;
            --version)
                log_info "iosramdisk.sh version $SCRIPT_VERSION"
                exit 0
                ;;
            # Add new option parsing here
            # Handles -u <UDID> option
            -u)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_DEVICE_UDID="${pre_parse_args[1]}"
                    log_debug "Parsed option -u: $OPT_DEVICE_UDID"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -u requires an argument."
                    usage; exit 1
                fi
                ;;
            # Handles -b <arguments> option
            -b)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_BOOT_ARGS="${pre_parse_args[1]}"
                    log_debug "Parsed option -b: $OPT_BOOT_ARGS"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -b requires an argument."
                    usage; exit 1
                fi
                ;;
            # Handles -k <file_path> option for custom iBSS/PongoOS
            -k)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_CUSTOM_IBSS_PATH="${pre_parse_args[1]}"
                    log_debug "Parsed option -k (custom iBSS/Pongo): $OPT_CUSTOM_IBSS_PATH"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -k requires a file path argument."
                    usage; exit 1
                fi
                ;;
            # Handles -K <file_path> option for custom KernelCache/KPF
            -K)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_CUSTOM_KERNEL_PATH="${pre_parse_args[1]}"
                    log_debug "Parsed option -K (custom Kernel): $OPT_CUSTOM_KERNEL_PATH"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -K requires a file path argument."
                    usage; exit 1
                fi
                ;;
            # Handles -R <file_path> option for custom Ramdisk
            -R)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_CUSTOM_RAMDISK_PATH="${pre_parse_args[1]}"
                    log_debug "Parsed option -R (custom Ramdisk): $OPT_CUSTOM_RAMDISK_PATH"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -R requires a file path argument."
                    usage; exit 1
                fi
                ;;
            # Handles -O <file_path> option for custom Overlay (conceptual)
            -O)
                if [[ -n "${pre_parse_args[1]}" && "${pre_parse_args[1]}" != -* ]]; then
                    OPT_CUSTOM_OVERLAY_PATH="${pre_parse_args[1]}"
                    log_debug "Parsed option -O (custom Overlay): $OPT_CUSTOM_OVERLAY_PATH"
                    shift_array pre_parse_args 2
                else
                    log_error "Option -O requires a file path argument."
                    usage; exit 1
                fi
                ;;
            create|boot|ssh|clean) # Existing main commands
                if [[ -z "$main_command" ]]; then
                    main_command="$arg"
                    shift_array pre_parse_args 1
                    # All subsequent arguments are for this command
                    command_args=("${pre_parse_args[@]}")
                    break # Stop pre-parsing, rest are command args
                else
                    # This case should ideally not be reached if commands are structured correctly
                    # (i.e., command not appearing as an argument to another command)
                    remaining_pre_parse_args+=("$arg")
                    shift_array pre_parse_args 1
                fi
                ;;
            *) # Argument not a global option or known command, save for later
                remaining_pre_parse_args+=("$arg")
                shift_array pre_parse_args 1
                ;;
        esac
    done

    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_debug "Debug mode enabled." # Log now that function is available
    fi

    # If main_command wasn't identified by specific keywords,
    # it might be the first item in remaining_pre_parse_args (if any).
    if [[ -z "$main_command" && ${#remaining_pre_parse_args[@]} -gt 0 ]]; then
        main_command="${remaining_pre_parse_args[0]}"
        command_args=("${remaining_pre_parse_args[@]:1}")
    elif [[ -z "$main_command" ]]; then
        # If still no main_command, and command_args is empty, means no command was given.
        if [[ ${#command_args[@]} -eq 0 ]]; then
            log_info "No command specified."
            # usage # This was here, but the DFU check below might show examples, then usage.
                    # If DFU examples are shown, we might not want to show full usage immediately after.
                    # The DFU example logic handles its own potential exit or continuation to usage.
        fi
    fi

    # Helper function to shift array elements (bash doesn't have a direct shift for arbitrary arrays)
    shift_array() {
        local -n arr_ref="$1" # Pass array by reference
        local num_to_shift="$2"
        arr_ref=("${arr_ref[@]:$num_to_shift}")
    }


    # Perform initial checks (OS and tools) - needed for most commands
    check_os
    check_tools

    log_debug "Ensuring suggested directories for custom boot files exist..."
    mkdir -p boot_files/pongo boot_files/kpf boot_files/ramdisks boot_files/overlays other/shsh
    # 'other/shsh' is likely already used/created by prepare_shsh, but -p makes it safe.

    # --- Conditional DFU Example Display ---
    # If no main command is specified by the user (e.g., create, boot),
    # and a DFU device is detected by the brief check,
    # display helpful command examples to the user.
    if [[ -z "$main_command" ]]; then # Only if no other command is specified
        if check_for_dfu_device_brief; then
            # Make sure display_dfu_command_examples is defined by this point
            display_dfu_command_examples
            # Optionally, exit here if you don't want to proceed to usage if no command was given
            # exit 0
        fi
        # If no DFU device and no command, fall through to usage
        if [[ ! -s /dev/stdin ]] && ! check_for_dfu_device_brief; then # check_for_dfu_device_brief is false
             usage
             exit 0
        fi
    fi
    # --- End Conditional DFU Example Display ---

    case "$main_command" in
        create)
            log_info "Starting 'create' command..."
            # Reset OPTIND for getopts if it's used multiple times or in subshells (good practice)
            OPTIND=1

            # Define local variables for create options before the loop
            local arg_ipsw_path=""
            local arg_device_id=""
            local arg_ios_version=""
            local arg_decryption_key=""
            local arg_build_variant="Install" # Default build variant
            local arg_ipsw_url=""

            # Manual parsing loop for create's arguments from command_args array
            local current_args_for_create=("${command_args[@]}")
            local final_unprocessed_args_for_create=()

            while [[ ${#current_args_for_create[@]} -gt 0 ]]; do
                local opt="${current_args_for_create[0]}"
                case "$opt" in
                    --ipsw)
                        arg_ipsw_path="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --device)
                        arg_device_id="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --version)
                        arg_ios_version="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --key)
                        arg_decryption_key="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --variant)
                        arg_build_variant="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --ipsw-url)
                        arg_ipsw_url="${current_args_for_create[1]}"
                        shift_array current_args_for_create 2
                        ;;
                    --a9-alt)
                        OPT_A9_ALT_FILES="true"
                        log_debug "Parsed option --a9-alt for create command."
                        shift_array current_args_for_create 1 # Shift one for the flag
                        ;;
                    -*) # An unknown option
                        log_error "Unknown option for create: $opt"
                        usage
                        exit 1
                        ;;
                    *)  # No more options, could be an unexpected positional argument
                        final_unprocessed_args_for_create+=("$opt")
                        shift_array current_args_for_create 1
                        ;;
                esac
            done

            if [[ ${#final_unprocessed_args_for_create[@]} -gt 0 ]]; then
                log_error "Unexpected arguments for create: ${final_unprocessed_args_for_create[*]}"
                usage
                exit 1
            fi

            # Validation for create command args
            if [[ -z "$arg_ipsw_path" && -z "$arg_ipsw_url" ]]; then
                log_error "Missing IPSW source for 'create': Please provide either --ipsw (local file) or --ipsw-url (direct URL)."
                usage; exit 1
            fi
            if [[ -z "$arg_device_id" ]]; then
                log_error "Missing --device for 'create'."
                usage; exit 1
            fi
            if [[ -z "$arg_ios_version" ]]; then
                log_error "Missing --version for 'create'."
                usage; exit 1
            fi


            # Extract major iOS version (e.g., "15" from "15.1")
            IOS_MAJOR_VERSION=$(echo "$arg_ios_version" | cut -d'.' -f1)
            if [[ -z "$IOS_MAJOR_VERSION" || ! "$IOS_MAJOR_VERSION" =~ ^[0-9]+$ ]]; then
                log_error "Could not determine major iOS version from '$arg_ios_version'. Please use format like X.Y or X.Y.Z."
            fi
            log_info "Extracted Major iOS Version: $IOS_MAJOR_VERSION"


            log_info "Device Identifier: $arg_device_id"
            log_info "iOS Version: $arg_ios_version (Major: $IOS_MAJOR_VERSION)"
            [[ -n "$arg_decryption_key" ]] && log_info "Decryption Key: Provided"
            log_info "Build Variant: $arg_build_variant"
            [[ -n "$arg_ipsw_path" ]] && log_info "IPSW Path (local): $arg_ipsw_path"
            [[ -n "$arg_ipsw_url" ]] && log_info "IPSW URL (direct): $arg_ipsw_url"


            setup_workspace "create_${arg_device_id}_${arg_ios_version}"

            if [[ -n "$arg_ipsw_path" && -z "$arg_ipsw_url" ]]; then
                log_warn "Local IPSW provided (--ipsw). Current implementation primarily uses IPSW URL for component download."
                log_warn "For full local IPSW processing, further implementation is needed. Attempting to find URL via ipsw.me for components."
            fi

            fetch_firmware_info "$arg_ipsw_url" "$arg_device_id" "$arg_ios_version" "$arg_build_variant"
            download_firmware_components

            ensure_dfu_mode
            pwn_device
            prepare_shsh

            process_iboot_component "iBSS" "$LOCAL_IBSS_PATH" "FINAL_IBSS_IMG4_PATH"

            local current_boot_args="rd=md0 debug=0x2014e -v wdt=-1"
            case "$DEVICE_CPID" in
                "8960" | "7000" | "7001")
                    log_info "CPID $DEVICE_CPID detected, adding NAND reformat boot arguments."
                    current_boot_args+=" nand-enable-reformat=1 -restore"
                    ;;
                *)
                    log_debug "CPID $DEVICE_CPID does not require NAND reformat boot arguments."
                    ;;
            esac
            process_iboot_component "iBEC" "$LOCAL_IBEC_PATH" "FINAL_IBEC_IMG4_PATH" "$current_boot_args"
            process_kernelcache
            process_devicetree
            process_trustcache
            process_ramdisk
            process_boot_logo
            finalize_ramdisk_creation

            log_info "Ramdisk creation process complete. Components are saved."
            log_info "'create' command finished."
            ;;
        boot)
            log_info "Starting 'boot' command..."
            local custom_ramdisk_path_arg="${command_args[0]}" # Optional path can be first arg after "boot"

            # If custom_ramdisk_path_arg is actually an option (starts with -), then it's not a path.
            if [[ "$custom_ramdisk_path_arg" == -* ]]; then
                 custom_ramdisk_path_arg="" # It's an option, not a path.
            elif [[ -n "$custom_ramdisk_path_arg" ]]; then
                # It was a path, shift it from command_args so it's not re-parsed by boot_ramdisk if it had options
                 shift_array command_args 1
            fi

            # At this point, command_args should only contain options if any were passed *after* the boot command
            # However, our current global option parsing consumes them before they reach here.
            # This part is more for future if we allow options after `boot` command.
            # For now, boot_ramdisk relies on global OPT_ variables.

            boot_ramdisk "$custom_ramdisk_path_arg"
            ;;
        ssh)
            log_info "Starting 'ssh' command..."
            if [[ ${#command_args[@]} -gt 0 ]]; then
                log_error "SSH command received unexpected arguments: ${command_args[*]}"
                usage
                exit 1
            fi
            connect_ssh
            ;;
        clean)
            log_info "Starting 'clean' command..."
            if [[ ${#command_args[@]} -gt 0 ]]; then
                log_error "Clean command received unexpected arguments: ${command_args[*]}"
                usage
                exit 1
            fi
            clean_output
            ;;
        *)
            log_error "Unknown command: $main_command"
            usage
            exit 1
            ;;
    esac
}

# ... (other functions remain the same)

# --- Firmware Information and Download Functions ---

fetch_firmware_info() {
    local provided_ipsw_url="$1"
    local device_id="$2"
    local ios_version="$3"
    local build_variant="$4" # Currently unused, but good to have for future BuildManifest parsing

    log_info "Fetching firmware information for $device_id, iOS $ios_version..."

    if [[ -n "$provided_ipsw_url" ]]; then
        IPSW_URL="$provided_ipsw_url"
        log_info "Using provided IPSW URL: $IPSW_URL"
    else
        log_info "No direct IPSW URL provided, querying ipsw.me API..."
        local api_url="https://api.ipsw.me/v4/device/${device_id}?type=ipsw"
        log_debug "Querying API URL: $api_url"

        local api_response
        api_response=$($CURL_BIN -sL "$api_url")
        if [[ $? -ne 0 || -z "$api_response" ]]; then
            log_error "Failed to fetch firmware list from ipsw.me or got empty response."
        fi

        log_debug "API Response: $api_response"

        IPSW_URL=$(echo "$api_response" | $JQ_BIN -r --arg ver "$ios_version" '.firmwares[] | select(.version==$ver) | .url')

        if [[ -z "$IPSW_URL" || "$IPSW_URL" == "null" ]]; then
            log_error "Could not find firmware URL for $device_id version $ios_version on ipsw.me. Response: $api_response"
        fi
        log_info "Found IPSW URL via ipsw.me: $IPSW_URL"
    fi

    log_info "Downloading BuildManifest.plist from IPSW..."
    LOCAL_BUILDMANIFEST_PATH="${CURRENT_TASK_WORK_DIR}/BuildManifest.plist"

    "$PZB_BIN" -g BuildManifest.plist "$IPSW_URL" > "$LOCAL_BUILDMANIFEST_PATH"
    if [[ $? -ne 0 || ! -s "$LOCAL_BUILDMANIFEST_PATH" ]]; then
        local pzb_output
        pzb_output=$("$PZB_BIN" -g BuildManifest.plist "$IPSW_URL" 2>&1)
        log_error "Failed to download BuildManifest.plist using pzb. Output: $pzb_output. Check IPSW URL and network."
    fi
    log_info "BuildManifest.plist downloaded to: $LOCAL_BUILDMANIFEST_PATH"

    log_info "Extracting component paths from BuildManifest.plist..."

    get_manifest_value() {
        local key_path="$1"
        local full_path="${MANIFEST_BUILD_IDENTITY_PATH}.${key_path}"
        "$PLISTBUDDY_BIN" -c "Print :${full_path}" "$LOCAL_BUILDMANIFEST_PATH" 2>/dev/null || echo ""
    }

    MANIFEST_IBSS_PATH=$(get_manifest_value "iBSS.Path")
    MANIFEST_IBEC_PATH=$(get_manifest_value "iBEC.Path")
    MANIFEST_KERNELCACHE_PATH=$(get_manifest_value "KernelCache.Path")
    MANIFEST_DEVICETREE_PATH=$(get_manifest_value "DeviceTree.Path")
    MANIFEST_RAMDISK_PATH=$(get_manifest_value "RestoreRamDisk.Info.Path")

    MANIFEST_TRUSTCACHE_PATH=$(get_manifest_value "StaticTrustCache.Path")
    if [[ -z "$MANIFEST_TRUSTCACHE_PATH" ]]; then
        MANIFEST_TRUSTCACHE_PATH=$(get_manifest_value "Firmware.StaticTrustCache.Path")
         if [[ -z "$MANIFEST_TRUSTCACHE_PATH" ]]; then
            MANIFEST_TRUSTCACHE_PATH=$(get_manifest_value "Firmware/arm64eSURStaticTrustCache.img4")
            if [[ -z "$MANIFEST_TRUSTCACHE_PATH" ]]; then
                 log_warn "StaticTrustCache.Path not found under common keys in BuildManifest. Might be normal for this iOS/device."
            fi
        fi
    fi

    log_info "Extracted Component Paths:"
    log_info "  iBSS: $MANIFEST_IBSS_PATH"
    log_info "  iBEC: $MANIFEST_IBEC_PATH"
    log_info "  KernelCache: $MANIFEST_KERNELCACHE_PATH"
    log_info "  DeviceTree: $MANIFEST_DEVICETREE_PATH"
    log_info "  RestoreRamDisk: $MANIFEST_RAMDISK_PATH"
    [[ -n "$MANIFEST_TRUSTCACHE_PATH" ]] && log_info "  StaticTrustCache: $MANIFEST_TRUSTCACHE_PATH" || log_info "  StaticTrustCache: Not found or not applicable"

    if [[ -z "$MANIFEST_IBEC_PATH" || -z "$MANIFEST_KERNELCACHE_PATH" || -z "$MANIFEST_RAMDISK_PATH" ]]; then
        log_error "Failed to extract one or more essential component paths (iBEC, KernelCache, RestoreRamDisk) from BuildManifest.plist. Check manifest structure or PlistBuddy compatibility."
    fi

    # Extract BUILD_ID for AppleWiki lookup
    local BUILD_ID=$($PLISTBUDDY_BIN -c "Print :ProductBuildVersion" "$LOCAL_BUILDMANIFEST_PATH" 2>/dev/null)
    if [[ -z "$BUILD_ID" ]]; then
        log_warn "Failed to extract ProductBuildVersion (BUILD_ID) from $LOCAL_BUILDMANIFEST_PATH. Cannot fetch specific IV/Keys from AppleWiki."
    else
        log_info "Extracted BuildID: $BUILD_ID for $device_id (iOS $ios_version)" # Use function args device_id, ios_version

        log_info "Attempting to fetch IV/Keys from TheAppleWiki for $device_id, iOS $ios_version (Build: $BUILD_ID)..."
        local applewiki_base_url="https://www.theapplewiki.com"
        local major_ios_x="${IOS_MAJOR_VERSION}.x" # Assumes IOS_MAJOR_VERSION is set globally or derived earlier
        local keys_overview_page_url="${applewiki_base_url}/wiki/Firmware_Keys/${major_ios_x}"
        local wiki_keys_json_path="${CURRENT_TASK_WORK_DIR}/applewiki_keys_${BUILD_ID}_${device_id}.json"

        log_debug "Fetching AppleWiki overview page: $keys_overview_page_url"
        local overview_content=$($CURL_BIN -sL --connect-timeout 10 --max-time 20 "$keys_overview_page_url") # Added timeouts

        if [[ -z "$overview_content" ]]; then
            log_warn "Failed to fetch or empty content from AppleWiki overview page: $keys_overview_page_url"
        else
            local device_id_escaped=${device_id//,/%2C}
            # Prioritize finding specific page by BuildID and full DeviceIdentifier
            local specific_page_path=$(echo "$overview_content" | grep -oE 'href="[^"]*'${BUILD_ID}'[^"]*'${device_id_escaped}'[^"]*"' | head -n1 | sed 's/href="//;s/"//')

            if [[ -z "$specific_page_path" ]]; then
                # Fallback: try with CPID if available (CPID would need to be known at this stage, or use model part)
                # For now, let's try a more general BuildID link on the overview page if specific device match fails.
                # This is less reliable. A better way would be to directly use device MODEL (e.g. iPhone10,3) if CPID isn't available yet.
                # The initial approach for arg_device_id (e.g. iPhone10,3) is usually what's in wiki URLs.
                log_debug "No specific page link found with BuildID and full DeviceIdentifier. Trying with BuildID and partial device model."
                local device_model_base=${device_id%%,*} # e.g., iPhone10 from iPhone10,3
                specific_page_path=$(echo "$overview_content" | grep -oE 'href="[^"]*'${BUILD_ID}'[^"]*'${device_model_base}'[^"]*"' | head -n1 | sed 's/href="//;s/"//')
                 if [[ -z "$specific_page_path" ]]; then
                    # Even more general fallback: just BUILD_ID. This is a last resort.
                    log_debug "No specific page link with partial model. Trying with BuildID only (less reliable)."
                    specific_page_path=$(echo "$overview_content" | grep -oE 'href="[^"]*'${BUILD_ID}'[^"]*"' | head -n1 | sed 's/href="//;s/"//')
                 fi
            fi

            if [[ -n "$specific_page_path" ]]; then
                local specific_key_page_url
                if [[ "$specific_page_path" == /* && "$specific_page_path" != //* ]]; then # Starts with / but not // (protocol relative)
                    specific_key_page_url="${applewiki_base_url}${specific_page_path}"
                elif [[ "$specific_page_path" == http* ]]; then # Already a full URL
                    specific_key_page_url="$specific_page_path"
                else # Potentially relative to current page, or needs base. Assume needs base for wiki structure.
                    specific_key_page_url="${applewiki_base_url}${specific_page_path}" # This might need /wiki/ prepended if path is just page title
                    # Correcting for paths like "/Key_Page_Title" vs "Key_Page_Title"
                    if [[ "$specific_page_path" != /* && "$specific_page_path" != http* ]]; then
                         specific_key_page_url="${applewiki_base_url}/wiki/${specific_page_path}" # Common wiki structure
                    fi
                fi

                log_debug "Fetching specific key page: $specific_key_page_url"
                local key_page_content=$($CURL_BIN -sL --connect-timeout 10 --max-time 20 "$specific_key_page_url")

                if [[ -z "$key_page_content" ]]; then
                    log_warn "Failed to fetch or empty content from specific key page: $specific_key_page_url"
                else
                    local json_link_suffix=$(echo "$key_page_content" | grep -i 'id="keypage-json-keys"' | grep -oE 'href="[^"]+"' | sed -e 's/href="//' -e 's/"//' -e 's/&amp;/\&/g' | head -n1)

                    if [[ -n "$json_link_suffix" ]]; then
                        local final_json_url
                        if [[ "$json_link_suffix" == /* && "$json_link_suffix" != //* ]]; then
                             final_json_url="${applewiki_base_url}${json_link_suffix}"
                        elif [[ "$json_link_suffix" == http* ]]; then
                             final_json_url="$json_link_suffix"
                        else # Assuming it's like /index.php?title=...
                             final_json_url="${applewiki_base_url}${json_link_suffix}"
                        fi

                        log_info "Fetching IV/Key JSON data from: $final_json_url"
                        "$CURL_BIN" -sL --connect-timeout 15 --max-time 30 "$final_json_url" -o "$wiki_keys_json_path"

                        if [[ -s "$wiki_keys_json_path" ]]; then
                            log_info "Successfully downloaded IV/Key JSON to $wiki_keys_json_path"

                            local ibss_data=$(jq -r '.cargoquery[]?.title | select(.component? | test("ibss"; "i"))' "$wiki_keys_json_path" 2>/dev/null)
                            if [[ -n "$ibss_data" ]]; then
                                DEVICE_IBSS_IV=$(echo "$ibss_data" | jq -r '.iv // empty' 2>/dev/null)
                                DEVICE_IBSS_KEY=$(echo "$ibss_data" | jq -r '.key // empty' 2>/dev/null)
                                [[ -n "$DEVICE_IBSS_IV" ]] && log_info "Found iBSS IV: $DEVICE_IBSS_IV"
                                [[ -n "$DEVICE_IBSS_KEY" ]] && log_info "Found iBSS Key: (hidden)" && log_debug "iBSS Key: $DEVICE_IBSS_KEY"
                            else
                                log_warn "Could not parse iBSS IV/Key from $wiki_keys_json_path (or iBSS section not found)."
                            fi

                            local ibec_data=$(jq -r '.cargoquery[]?.title | select(.component? | test("ibec"; "i"))' "$wiki_keys_json_path" 2>/dev/null)
                            if [[ -n "$ibec_data" ]]; then
                                DEVICE_IBEC_IV=$(echo "$ibec_data" | jq -r '.iv // empty' 2>/dev/null)
                                DEVICE_IBEC_KEY=$(echo "$ibec_data" | jq -r '.key // empty' 2>/dev/null)
                                [[ -n "$DEVICE_IBEC_IV" ]] && log_info "Found iBEC IV: $DEVICE_IBEC_IV"
                                [[ -n "$DEVICE_IBEC_KEY" ]] && log_info "Found iBEC Key: (hidden)" && log_debug "iBEC Key: $DEVICE_IBEC_KEY"
                            else
                                log_warn "Could not parse iBEC IV/Key from $wiki_keys_json_path (or iBEC section not found)."
                            fi
                        else
                            log_warn "Failed to download or empty IV/Key JSON from $final_json_url"
                        fi
                    else
                        log_warn "Could not find JSON data link on key page: $specific_key_page_url. Check for 'View JSON' link with id 'keypage-json-keys'."
                    fi
                fi
            else
                log_warn "Could not find specific key page link for $device_id Build $BUILD_ID on $keys_overview_page_url"
            fi
        fi
    fi # End of BUILD_ID check
}

download_firmware_components() {
    log_info "Downloading firmware components from IPSW: $IPSW_URL"

    if [[ -z "$CURRENT_TASK_WORK_DIR" ]]; then
        log_error "CURRENT_TASK_WORK_DIR is not set. Call setup_workspace first."
    fi

    download_component() {
        local component_manifest_path="$1"
        local component_name="$2"

        if [[ -z "$component_manifest_path" ]]; then
            log_warn "Manifest path for $component_name is empty, skipping download."
            return
        fi

        local local_filename=$(basename "$component_manifest_path")
        local local_path="${CURRENT_TASK_WORK_DIR}/${local_filename}"

        log_info "Downloading $component_name ($component_manifest_path) to $local_path..."
        "$PZB_BIN" -g "$component_manifest_path" "$IPSW_URL" > "$local_path"
        if [[ $? -ne 0 || ! -s "$local_path" ]]; then
            local pzb_output=$("$PZB_BIN" -g "$component_manifest_path" "$IPSW_URL" 2>&1)
            log_error "Failed to download $component_name. pzb output: $pzb_output"
        fi
        log_info "$component_name downloaded successfully to $local_path"

        local global_var_name="LOCAL_$(echo "$component_name" | tr '[:lower:]' '[:upper:]')_PATH"
        declare -g "$global_var_name"="$local_path"
        log_debug "$global_var_name set to: ${!global_var_name}"
    }

    download_component "$MANIFEST_IBSS_PATH" "IBSS"
    download_component "$MANIFEST_IBEC_PATH" "IBEC"
    download_component "$MANIFEST_KERNELCACHE_PATH" "KERNELCACHE"
    download_component "$MANIFEST_DEVICETREE_PATH" "DEVICETREE"
    download_component "$MANIFEST_RAMDISK_PATH" "RAMDISK"
    if [[ -n "$MANIFEST_TRUSTCACHE_PATH" ]]; then
        download_component "$MANIFEST_TRUSTCACHE_PATH" "TRUSTCACHE"
    else
        log_info "TrustCache manifest path not set, skipping its download."
    fi

    log_info "All specified firmware components downloaded."
}

# --- Device Interaction Functions ---

# --- Brief DFU Device Check ---
# Performs a quick, non-blocking check for a device in DFU mode.
# Used to decide whether to show DFU command examples if no other command is given.
# Does not loop or wait extensively for a device.
# Globals used: $IRECOVERY_BIN, log_debug()
# Returns: 0 if DFU device found, 1 otherwise.
check_for_dfu_device_brief() {
    log_debug "Briefly checking for DFU device..."
    local irecovery_output
    if ( command -v timeout &>/dev/null ); then
        irecovery_output=$(timeout 0.5s $IRECOVERY_BIN -q 2>&1)
    else
        irecovery_output=$($IRECOVERY_BIN -q 2>&1)
    fi
    local irecovery_exit_code=$?

    if [[ $irecovery_exit_code -eq 0 ]]; then
        local mode=$(echo "$irecovery_output" | grep -o 'MODE: [^ ]*' | awk '{print $2}')
        if [[ "$mode" == "DFU" ]]; then
            log_debug "DFU device found by brief check."
            return 0
        fi
    fi
    log_debug "No DFU device found by brief check or device not in DFU mode."
    return 1
}

ensure_dfu_mode() {
    log_info "Attempting to detect device in DFU mode..."
    DEVICE_CPID=""
    DEVICE_ECID=""
    DEVICE_MODEL_RAW=""
    DEVICE_PWND_STATE="NO"

    while true; do
        local irecovery_output
        irecovery_output=$($IRECOVERY_BIN -q 2>&1)
        local irecovery_exit_code=$?

        if [[ $irecovery_exit_code -eq 0 ]]; then
            local mode=$(echo "$irecovery_output" | grep -o 'MODE: [^ ]*' | awk '{print $2}')
            local cpid_line=$(echo "$irecovery_output" | grep 'CPID:')
            local ecid_line=$(echo "$irecovery_output" | grep 'ECID:')
            local pwnd_line=$(echo "$irecovery_output" | grep 'PWND:')
            local model_line=$(echo "$irecovery_output" | grep 'MODEL:')

            if [[ "$mode" == "DFU" ]]; then
                DEVICE_CPID=$(echo "$cpid_line" | awk '{print $2}' | cut -d',' -f1)
                DEVICE_ECID=$(echo "$ecid_line" | awk '{print $2}' | cut -d',' -f1)
                DEVICE_MODEL_RAW=$(echo "$model_line" | awk '{print $2}' | cut -d',' -f1)

                if [[ -n "$pwnd_line" ]]; then
                    DEVICE_PWND_STATE="YES"
                else
                    DEVICE_PWND_STATE="NO"
                fi
                log_info "Device detected in DFU mode. CPID: $DEVICE_CPID, ECID: $DEVICE_ECID, MODEL: $DEVICE_MODEL_RAW, PWNED: $DEVICE_PWND_STATE"
                # display_dfu_command_examples # Call is now in main()
                break
            else
                log_info "Device not in DFU mode (Current mode: $mode). Waiting... (Ctrl+C to cancel)"
            fi
        else
            log_info "No device detected by irecovery. Waiting for device in DFU mode... (Ctrl+C to cancel)"
        fi
        sleep 3
    done

    if [[ -z "$DEVICE_CPID" || -z "$DEVICE_ECID" || -z "$DEVICE_MODEL_RAW" ]]; then
        log_error "Failed to detect device CPID, ECID, or MODEL in DFU mode. Exiting."
    fi
}

pwn_device() {
    if [[ "$DEVICE_PWND_STATE" == "YES" ]]; then
        log_info "Device reports as already pwned. Skipping gaster."
        return
    fi

    if [[ -z "$GASTER_BIN" ]]; then
        log_error "GASTER_BIN not set. Cannot pwn device."
    fi

    log_info "Powning device with gaster..."
    if "$GASTER_BIN" pwn > >(while IFS= read -r line; do log_debug "gaster pwn: $line"; done) 2> >(while IFS= read -r line; do log_error "gaster pwn_err: $line"; done && false); then
        log_info "gaster pwn command executed."
    else
        log_error "gaster pwn failed. Check logs for details. Ensure device is in DFU and gaster is compatible."
    fi

    log_info "Running gaster reset..."
    if "$GASTER_BIN" reset > >(while IFS= read -r line; do log_debug "gaster reset: $line"; done) 2> >(while IFS= read -r line; do log_error "gaster reset_err: $line"; done && false); then
        log_info "gaster reset command executed."
    else
        log_warn "gaster reset failed. This might be okay, continuing..."
    fi

    log_info "Device pwn attempt finished. Re-verifying PWND state with irecovery."
    local irecovery_output
    irecovery_output=$($IRECOVERY_BIN -q 2>&1)
    local pwnd_line=$(echo "$irecovery_output" | grep 'PWND:')
    if [[ -n "$pwnd_line" ]]; then
        DEVICE_PWND_STATE="YES"
        log_info "Device successfully pwned and is now in pwnDFU mode."
    else
        log_error "Device does not report as pwned after gaster attempt. Please check gaster output and device compatibility."
    fi
}

prepare_shsh() {
    if [[ -z "$DEVICE_CPID" ]]; then
        log_error "Device CPID not set. Cannot prepare SHSH blob. Ensure DFU mode was detected."
    fi

    local shsh_dir="other/shsh"
    SHSH_BLOB_PATH="${shsh_dir}/${DEVICE_CPID}.shsh"

    if [[ ! -d "$shsh_dir" ]]; then
        log_warn "SHSH directory '$shsh_dir' does not exist. Please create it and add SHSH blobs."
    fi

    if [[ ! -f "$SHSH_BLOB_PATH" ]]; then
        log_error "SHSH blob not found at $SHSH_BLOB_PATH. Please ensure the correct SHSH blob for CPID $DEVICE_CPID is placed there."
    fi

    log_info "Preparing SHSH blob for signing using: $SHSH_BLOB_PATH"
    IM4M_PATH="${CURRENT_TASK_WORK_DIR}/pwned.im4m"

    if [[ -z "$IMG4TOOL_BIN" ]]; then
        log_error "IMG4TOOL_BIN is not set. Cannot process SHSH."
    fi

    "$IMG4TOOL_BIN" -e --shsh "$SHSH_BLOB_PATH" -m "$IM4M_PATH"
    if [[ $? -ne 0 || ! -s "$IM4M_PATH" ]]; then
        log_warn "img4tool with --shsh failed, trying with -s..."
        "$IMG4TOOL_BIN" -e -s "$SHSH_BLOB_PATH" -m "$IM4M_PATH"
        if [[ $? -ne 0 || ! -s "$IM4M_PATH" ]]; then
            log_error "Failed to create IM4M from SHSH blob using img4tool (tried --shsh and -s). Path: $SHSH_BLOB_PATH"
        fi
    fi

    log_info "IM4M successfully created at: $IM4M_PATH"
}

# --- Component Processing Functions ---

process_iboot_component() {
    local component_name="$1"
    local local_path_to_component="$2"
    local output_img4_path_var_name="$3"
    local boot_args="$4"

    log_info "Processing $component_name from $local_path_to_component..."

    if [[ -z "$local_path_to_component" || !-f "$local_path_to_component" ]]; then
        log_error "$component_name input file '$local_path_to_component' not found or path is empty."
    fi

    local dec_path="${CURRENT_TASK_WORK_DIR}/${component_name}.dec"
    local patch_input_path=""

    log_info "Attempting to decrypt $component_name with gaster..."
    "$GASTER_BIN" decrypt "$local_path_to_component" "$dec_path" > >(while IFS= read -r line; do log_debug "gaster decrypt $component_name: $line"; done) 2> >(while IFS= read -r line; do log_warn "gaster decrypt $component_name err: $line"; done && false)
    if [[ $? -eq 0 && -s "$dec_path" ]]; then
        patch_input_path="$dec_path"
        log_info "Gaster decryption for $component_name successful: $dec_path"
    else
        log_warn "Gaster decryption for $component_name failed or produced an empty file. Using original file for patching: $local_path_to_component"
        patch_input_path="$local_path_to_component"
        if [[ -f "$dec_path" && ! -s "$dec_path" ]]; then
            rm -f "$dec_path"
        fi
    fi

    local patched_path="${CURRENT_TASK_WORK_DIR}/${component_name}.patched"
    log_info "Patching $component_name from $patch_input_path..."

    local patch_cmd_array=("$IBOOT64PATCHER_BIN" "$patch_input_path" "$patched_path")
    if [[ -n "$boot_args" ]]; then
        log_info "Using boot arguments for $component_name: $boot_args"
        patch_cmd_array+=("-b" "$boot_args")
    fi

    "${patch_cmd_array[@]}" > >(while IFS= read -r line; do log_debug "iBoot64Patcher $component_name: $line"; done) 2> >(while IFS= read -r line; do log_error "iBoot64Patcher $component_name err: $line"; done && false)
    if [[ $? -ne 0 || ! -s "$patched_path" ]]; then
        log_error "Failed to patch $component_name using iBoot64Patcher. Input: $patch_input_path. Output: $patched_path might be missing or empty."
    fi
    log_info "$component_name patched successfully: $patched_path"

    local final_img4_path="${CURRENT_TASK_WORK_DIR}/${component_name}.img4"
    local img4_type_tag=$(echo "$component_name" | tr '[:upper:]' '[:lower:]')

    log_info "Packing $component_name to .img4 format as $final_img4_path with type tag '$img4_type_tag'..."
    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_error "IM4M path ($IM4M_PATH) is not set or file not found. Cannot pack $component_name."
    fi

    "$IMG4_BIN" -i "$patched_path" -o "$final_img4_path" -M "$IM4M_PATH" -A -T "$img4_type_tag"
    if [[ $? -ne 0 || ! -s "$final_img4_path" ]]; then
        log_error "Failed to pack $component_name to .img4 using img4. Input: $patched_path. Output: $final_img4_path might be missing or empty."
    fi

    declare -g "$output_img4_path_var_name=$final_img4_path"
    log_info "$component_name processed and packed to ${!output_img4_path_var_name}"
}

process_kernelcache() {
    log_info "Processing KernelCache from $LOCAL_KERNELCACHE_PATH..."

    if [[ -z "$LOCAL_KERNELCACHE_PATH" || ! -f "$LOCAL_KERNELCACHE_PATH" ]]; then
        log_error "KernelCache input file '$LOCAL_KERNELCACHE_PATH' not found or path is empty."
    fi
    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_error "IM4M path ($IM4M_PATH) is not set or file not found. Cannot process KernelCache."
    fi

    local kcache_raw="${CURRENT_TASK_WORK_DIR}/kcache.raw"
    local kcache_patched="${CURRENT_TASK_WORK_DIR}/kcache.patched"
    local kc_bpatch="${CURRENT_TASK_WORK_DIR}/kc.bpatch"
    local final_kc_img4_path="${CURRENT_TASK_WORK_DIR}/kernelcache.img4"

    log_info "Extracting raw kernel from downloaded KernelCache: $LOCAL_KERNELCACHE_PATH to $kcache_raw"
    "$IMG4_BIN" -i "$LOCAL_KERNELCACHE_PATH" -o "$kcache_raw"
    if [[ $? -ne 0 || ! -s "$kcache_raw" ]]; then
        log_error "Failed to extract raw kernel using img4. Input: $LOCAL_KERNELCACHE_PATH. Output: $kcache_raw might be missing or empty."
    fi
    log_info "Raw kernel extracted to $kcache_raw"

    log_info "Patching KernelCache with KPlooshFinder..."
    "$KPLOOSHFINDER_BIN" "$kcache_raw" "$kcache_patched"
    if [[ $? -ne 0 || ! -s "$kcache_patched" ]]; then
        log_error "Failed to patch KernelCache using KPlooshFinder. Input: $kcache_raw. Output: $kcache_patched might be missing or empty."
    fi
    log_info "KernelCache patched with KPlooshFinder: $kcache_patched"

    log_info "Diffing KernelCache with kerneldiff to create bpatch file..."
    "$KERNELDIFF_BIN" "$kcache_raw" "$kcache_patched" "$kc_bpatch"
    if [[ $? -ne 0 || ! -s "$kc_bpatch" ]]; then
        log_error "Failed to create bpatch file using kerneldiff. Inputs: $kcache_raw, $kcache_patched. Output: $kc_bpatch might be missing or empty."
    fi
    log_info "KernelCache bpatch created: $kc_bpatch"

    local final_kernel_input_for_img4="$LOCAL_KERNELCACHE_PATH" # Default is the original downloaded kernel path for img4 (to be patched by img4)
    local use_compression=false

    # Check for A10+ CPIDs (add all relevant A10+ CPIDs here)
    if [[ "$DEVICE_CPID" == "8010" || "$DEVICE_CPID" == "8011" || "$DEVICE_CPID" == "8012" || "$DEVICE_CPID" == "8015" ]]; then
        if [[ "$IOS_MAJOR_VERSION" -le 13 ]]; then
            use_compression=true
        fi
    fi

    if [[ "$use_compression" == "true" ]]; then
        log_info "A10+ device on iOS $IOS_MAJOR_VERSION (<=13) detected. Compressing kernelcache with LZSS..."
        local kcache_compressed_im4p="${CURRENT_TASK_WORK_DIR}/kcache_compressed.im4p"

        if [[ -z "$IMG4TOOL_BIN" || ! -x "$IMG4TOOL_BIN" ]]; then
            log_error "IMG4TOOL_BIN is not set or not executable. Cannot compress kernelcache. Please ensure img4tool is in tools directory."
        fi
        # Input to img4tool -c should be the *patched* kernel payload, not the original IM4P or raw extracted.
        # kcache_patched is the output of KPlooshFinder.
        "$IMG4TOOL_BIN" -c "$kcache_compressed_im4p" -t rkrn --compression complzss "$kcache_patched"
        if [[ $? -ne 0 || ! -s "$kcache_compressed_im4p" ]]; then
            log_error "Failed to compress kernelcache using img4tool. Input: $kcache_patched"
        fi
        log_info "Kernelcache compressed to $kcache_compressed_im4p"
        final_kernel_input_for_img4="$kcache_compressed_im4p" # This compressed file will be signed by img4
    fi

    log_info "Packing KernelCache to .img4 format..."
    local img4_pack_args_kc=()
    if [[ "$use_compression" == "true" ]]; then
        # Input is the compressed .im4p from img4tool. We are essentially re-signing/re-manifesting it.
        # The bpatch (-P) is not applicable here as the payload is already transformed.
        img4_pack_args_kc=("-i" "$final_kernel_input_for_img4" "-o" "$final_kc_img4_path" "-M" "$IM4M_PATH" "-T" "rkrn")
    else
        # Input is the original kernel path, apply bpatch.
        img4_pack_args_kc=("-i" "$LOCAL_KERNELCACHE_PATH" "-o" "$final_kc_img4_path" "-M" "$IM4M_PATH" "-T" "rkrn" "-P" "$kc_bpatch")
        if [[ "$OS_TYPE" == "Linux" ]]; then # -J might not be needed or compatible if input is from img4tool
            log_debug "Linux OS detected, adding -J (skip CertID check) to img4 pack command for non-compressed kernel."
            img4_pack_args_kc+=("-J")
        fi
    fi

    "$IMG4_BIN" "${img4_pack_args_kc[@]}"
    if [[ $? -ne 0 || ! -s "$final_kc_img4_path" ]]; then
        log_error "Failed to pack KernelCache to .img4 using img4. Output: $final_kc_img4_path might be missing or empty."
    fi

    declare -g FINAL_KERNELCACHE_IMG4_PATH="$final_kc_img4_path"
    log_info "KernelCache processed and packed to $FINAL_KERNELCACHE_IMG4_PATH"
}

process_devicetree() {
    log_info "Processing DeviceTree from $LOCAL_DEVICETREE_PATH..."

    if [[ -z "$LOCAL_DEVICETREE_PATH" || ! -f "$LOCAL_DEVICETREE_PATH" ]]; then
        log_error "DeviceTree input file '$LOCAL_DEVICETREE_PATH' not found or path is empty. Cannot proceed."
    fi
    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_error "IM4M path ($IM4M_PATH) is not set or file not found. Cannot process DeviceTree."
    fi

    local final_dt_img4_path="${CURRENT_TASK_WORK_DIR}/devicetree.img4"

    log_info "Packing DeviceTree to .img4 format: $final_dt_img4_path"
    "$IMG4_BIN" -i "$LOCAL_DEVICETREE_PATH" -o "$final_dt_img4_path" -M "$IM4M_PATH" -A -T "rdtr"
    if [[ $? -ne 0 || ! -s "$final_dt_img4_path" ]]; then
        log_error "Failed to pack DeviceTree to .img4 using img4. Input: $LOCAL_DEVICETREE_PATH. Output: $final_dt_img4_path might be missing or empty."
    fi

    declare -g FINAL_DEVICETREE_IMG4_PATH="$final_dt_img4_path"
    log_info "DeviceTree processed and packed to $FINAL_DEVICETREE_IMG4_PATH"
}

process_trustcache() {
    log_info "Processing TrustCache from $LOCAL_TRUSTCACHE_PATH..."

    if [[ -z "$LOCAL_TRUSTCACHE_PATH" ]]; then
        log_info "LOCAL_TRUSTCACHE_PATH is not set (TrustCache may not exist for this firmware or was not found). Skipping TrustCache processing."
        FINAL_TRUSTCACHE_IMG4_PATH=""
        return 0
    fi
    if [[ ! -f "$LOCAL_TRUSTCACHE_PATH" ]]; then
        log_warn "TrustCache file '$LOCAL_TRUSTCACHE_PATH' not found, though path was set. Skipping TrustCache processing."
        FINAL_TRUSTCACHE_IMG4_PATH=""
        return 0
    fi

    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_error "IM4M path ($IM4M_PATH) is not set or file not found. Cannot process TrustCache."
    fi

    local final_tc_img4_path="${CURRENT_TASK_WORK_DIR}/trustcache.img4"

    log_info "Packing TrustCache to .img4 format: $final_tc_img4_path"
    "$IMG4_BIN" -i "$LOCAL_TRUSTCACHE_PATH" -o "$final_tc_img4_path" -M "$IM4M_PATH" -A -T "rtsc"
    if [[ $? -ne 0 || ! -s "$final_tc_img4_path" ]]; then
        log_error "Failed to pack TrustCache to .img4 using img4. Input: $LOCAL_TRUSTCACHE_PATH. Output: $final_tc_img4_path might be missing or empty."
    fi

    declare -g FINAL_TRUSTCACHE_IMG4_PATH="$final_tc_img4_path"
    log_info "TrustCache processed and packed to $FINAL_TRUSTCACHE_IMG4_PATH"
}

process_ramdisk() {
    log_info "Processing Ramdisk DMG from $LOCAL_RAMDISK_PATH..."

    if [[ -z "$LOCAL_RAMDISK_PATH" || ! -f "$LOCAL_RAMDISK_PATH" ]]; then
        log_error "Ramdisk DMG input file '$LOCAL_RAMDISK_PATH' not found or path is empty."
    fi
    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_error "IM4M path ($IM4M_PATH) is not set or file not found. Cannot process Ramdisk."
    fi

    local ramdisk_dec_path="${CURRENT_TASK_WORK_DIR}/ramdisk.dec.dmg"
    local ramdisk_modified_path="${CURRENT_TASK_WORK_DIR}/ramdisk.modified.dmg"
    local final_ramdisk_img4_path="${CURRENT_TASK_WORK_DIR}/ramdisk.img4"
    local ssh_mount_point="${CURRENT_TASK_WORK_DIR}/SSHRD_mnt"

    log_info "Extracting raw DMG from $LOCAL_RAMDISK_PATH to $ramdisk_dec_path..."
    "$IMG4_BIN" -i "$LOCAL_RAMDISK_PATH" -o "$ramdisk_dec_path"
    if [[ $? -ne 0 || ! -s "$ramdisk_dec_path" ]]; then
        log_error "Failed to extract raw DMG using img4. Input: $LOCAL_RAMDISK_PATH. Output: $ramdisk_dec_path might be missing or empty."
    fi
    log_info "Raw DMG extracted to $ramdisk_dec_path"

    local ssh_tar_to_use="ssh.tar"
    if [[ "$DEVICE_MODEL_RAW" == *"j42dap"* || "$DEVICE_MODEL_RAW" == *"j105ap"* ]]; then
        ssh_tar_to_use="atvssh.tar"
        log_info "Device model $DEVICE_MODEL_RAW detected, selecting $ssh_tar_to_use."
    elif [[ "$DEVICE_CPID" == "8012" ]]; then
        ssh_tar_to_use="t2ssh.tar"
        log_info "Device CPID $DEVICE_CPID (T2 Mac) detected, selecting $ssh_tar_to_use."
    else
        log_info "Using default SSH tarball: $ssh_tar_to_use for device model $DEVICE_MODEL_RAW / CPID $DEVICE_CPID."
    fi

    local selected_ssh_tar_archive_path="resources/sshtars/${ssh_tar_to_use}.gz"
    local final_selected_ssh_tar_path="${CURRENT_TASK_WORK_DIR}/${ssh_tar_to_use}"

    if [[ ! -f "$selected_ssh_tar_archive_path" ]]; then
        log_error "SSH tarball archive not found at $selected_ssh_tar_archive_path. Please ensure it exists."
    fi

    log_info "Decompressing $selected_ssh_tar_archive_path to $final_selected_ssh_tar_path..."
    gzip -dc "$selected_ssh_tar_archive_path" > "$final_selected_ssh_tar_path"
    if [[ $? -ne 0 || ! -s "$final_selected_ssh_tar_path" ]]; then
        log_error "Failed to decompress SSH tarball $selected_ssh_tar_archive_path."
    fi
    log_info "SSH tarball decompressed successfully."

    log_info "Copying $ramdisk_dec_path to $ramdisk_modified_path for modification..."
    cp "$ramdisk_dec_path" "$ramdisk_modified_path"
    if [[ $? -ne 0 ]]; then
        log_error "Failed to copy $ramdisk_dec_path to $ramdisk_modified_path."
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        log_info "Modifying ramdisk for Darwin using hdiutil and gtar..."

        log_debug "Resizing ramdisk $ramdisk_modified_path to 250MB..."
        "$HDIUTIL_BIN" resize -size 250MB "$ramdisk_modified_path" || log_error "hdiutil resize (to 250MB) failed for $ramdisk_modified_path."

        mkdir -p "$ssh_mount_point" || log_error "Failed to create mount point $ssh_mount_point."

        log_debug "Attaching ramdisk $ramdisk_modified_path to $ssh_mount_point..."
        "$HDIUTIL_BIN" attach -mountpoint "$ssh_mount_point" -nobrowse -owners off "$ramdisk_modified_path" || log_error "hdiutil attach failed for $ramdisk_modified_path."

        log_info "Injecting SSH tools from $final_selected_ssh_tar_path into $ssh_mount_point/..."
        if [[ -z "$GTAR_BIN" ]]; then log_error "GTAR_BIN is not set."; fi
        "$GTAR_BIN" -x --no-overwrite-dir -f "$final_selected_ssh_tar_path" -C "$ssh_mount_point/" || log_error "gtar extraction failed into $ssh_mount_point."

        log_debug "Detaching ramdisk from $ssh_mount_point..."
        "$HDIUTIL_BIN" detach -force "$ssh_mount_point" || log_error "hdiutil detach failed for $ssh_mount_point."

        log_debug "Resizing ramdisk $ramdisk_modified_path to minimum sectors..."
        "$HDIUTIL_BIN" resize -sectors min "$ramdisk_modified_path" || log_error "hdiutil resize (to min sectors) failed for $ramdisk_modified_path."

        log_info "Ramdisk modification for Darwin complete."

    elif [[ "$OS_TYPE" == "Linux" ]]; then
        log_info "Modifying ramdisk for Linux using hfsplus..."
        if [[ -z "$HFSPLUS_BIN" ]]; then log_error "HFSPLUS_BIN is not set."; fi

        log_debug "Growing ramdisk $ramdisk_modified_path by 250MB..."
        "$HFSPLUS_BIN" "$ramdisk_modified_path" grow 250000000 || log_error "hfsplus grow failed for $ramdisk_modified_path."

        log_info "Injecting SSH tools from $final_selected_ssh_tar_path into ramdisk..."
        "$HFSPLUS_BIN" "$ramdisk_modified_path" untar "$final_selected_ssh_tar_path" || log_error "hfsplus untar failed for $ramdisk_modified_path with $final_selected_ssh_tar_path."

        log_info "Ramdisk modification for Linux complete."
    else
        log_error "Unsupported OS_TYPE '$OS_TYPE' for ramdisk modification."
    fi

    log_info "Packing modified ramdisk $ramdisk_modified_path to .img4 format..."
    "$IMG4_BIN" -i "$ramdisk_modified_path" -o "$final_ramdisk_img4_path" -M "$IM4M_PATH" -A -T "rdsk"
    if [[ $? -ne 0 || ! -s "$final_ramdisk_img4_path" ]]; then
        log_error "Failed to pack modified ramdisk to .img4. Input: $ramdisk_modified_path. Output: $final_ramdisk_img4_path might be missing or empty."
    fi

    declare -g FINAL_RAMDISK_IMG4_PATH="$final_ramdisk_img4_path"
    log_info "Ramdisk processed and packed to $FINAL_RAMDISK_IMG4_PATH"
}

process_boot_logo() {
    log_info "Processing Boot Logo..."
    FINAL_BOOTLOGO_IMG4_PATH=""

    local boot_logo_source_path="other/bootlogo.im4p"

    if [[ ! -f "$boot_logo_source_path" ]]; then
        log_warn "Boot logo source file not found at '$boot_logo_source_path'. Skipping boot logo processing."
        return 0
    fi
    if [[ ! -r "$boot_logo_source_path" ]]; then
        log_warn "Boot logo source file '$boot_logo_source_path' is not readable. Skipping."
        return 0
    fi

    if [[ -z "$IM4M_PATH" || ! -f "$IM4M_PATH" ]]; then
        log_warn "IM4M path ($IM4M_PATH) is not set or file not found. Cannot process Boot Logo. Skipping."
        return 0
    fi

    local final_logo_img4_path="${CURRENT_TASK_WORK_DIR}/logo.img4"

    log_info "Packing Boot Logo from $boot_logo_source_path to .img4 format: $final_logo_img4_path"
    "$IMG4_BIN" -i "$boot_logo_source_path" -o "$final_logo_img4_path" -M "$IM4M_PATH" -A -T "rlgo"
    if [[ $? -ne 0 || ! -s "$final_logo_img4_path" ]]; then
        log_warn "Failed to pack Boot Logo using img4. Input: $boot_logo_source_path. Output: $final_logo_img4_path might be missing or empty. Continuing without custom boot logo."
        return 0
    fi

    declare -g FINAL_BOOTLOGO_IMG4_PATH="$final_logo_img4_path"
    log_info "Boot Logo processed and packed to $FINAL_BOOTLOGO_IMG4_PATH"
}

finalize_ramdisk_creation() {
    log_info "Finalizing ramdisk creation and saving components..."

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log_info "Main output directory '$OUTPUT_DIR' does not exist. Creating it..."
        mkdir -p "$OUTPUT_DIR" || log_error "Failed to create main output directory: $OUTPUT_DIR"
    fi

    local timestamp=$(date +%Y%m%d-%H%M%S)
    local current_ramdisk_output_subdir="${OUTPUT_DIR}/${DEVICE_MODEL_RAW}_${arg_ios_version}_${timestamp}"

    log_info "Creating ramdisk output subdirectory: $current_ramdisk_output_subdir"
    mkdir -p "$current_ramdisk_output_subdir"
    if [[ $? -ne 0 ]]; then
        log_error "Failed to create ramdisk output subdirectory: $current_ramdisk_output_subdir"
    fi

    log_info "Saving ramdisk components to $current_ramdisk_output_subdir"

    local component_paths=()
    [[ -n "$FINAL_IBSS_IMG4_PATH" && -f "$FINAL_IBSS_IMG4_PATH" ]] && component_paths+=("$FINAL_IBSS_IMG4_PATH")
    [[ -n "$FINAL_IBEC_IMG4_PATH" && -f "$FINAL_IBEC_IMG4_PATH" ]] && component_paths+=("$FINAL_IBEC_IMG4_PATH")
    [[ -n "$FINAL_KERNELCACHE_IMG4_PATH" && -f "$FINAL_KERNELCACHE_IMG4_PATH" ]] && component_paths+=("$FINAL_KERNELCACHE_IMG4_PATH")
    [[ -n "$FINAL_DEVICETREE_IMG4_PATH" && -f "$FINAL_DEVICETREE_IMG4_PATH" ]] && component_paths+=("$FINAL_DEVICETREE_IMG4_PATH")
    [[ -n "$FINAL_RAMDISK_IMG4_PATH" && -f "$FINAL_RAMDISK_IMG4_PATH" ]] && component_paths+=("$FINAL_RAMDISK_IMG4_PATH")

    if [[ -n "$FINAL_TRUSTCACHE_IMG4_PATH" && -f "$FINAL_TRUSTCACHE_IMG4_PATH" ]]; then
        component_paths+=("$FINAL_TRUSTCACHE_IMG4_PATH")
    fi
    if [[ -n "$FINAL_BOOTLOGO_IMG4_PATH" && -f "$FINAL_BOOTLOGO_IMG4_PATH" ]]; then
        component_paths+=("$FINAL_BOOTLOGO_IMG4_PATH")
    fi

    for component_path in "${component_paths[@]}"; do
        if [[ -n "$component_path" && -f "$component_path" ]]; then
            log_debug "Moving $(basename "$component_path") to $current_ramdisk_output_subdir/"
            mv "$component_path" "$current_ramdisk_output_subdir/"
            if [[ $? -ne 0 ]]; then
                log_warn "Failed to move $(basename "$component_path") to $current_ramdisk_output_subdir."
            fi
        else
            log_warn "Component path '$component_path' is empty or file does not exist. Skipping move."
        fi
    done

    local info_file_path="${current_ramdisk_output_subdir}/info.txt"
    log_info "Creating information file: $info_file_path"

    local ibss_bn=$( [[ -n "$FINAL_IBSS_IMG4_PATH" ]] && basename "$FINAL_IBSS_IMG4_PATH" || echo "N/A" )
    local ibec_bn=$( [[ -n "$FINAL_IBEC_IMG4_PATH" ]] && basename "$FINAL_IBEC_IMG4_PATH" || echo "N/A" )
    local kc_bn=$( [[ -n "$FINAL_KERNELCACHE_IMG4_PATH" ]] && basename "$FINAL_KERNELCACHE_IMG4_PATH" || echo "N/A" )
    local dt_bn=$( [[ -n "$FINAL_DEVICETREE_IMG4_PATH" ]] && basename "$FINAL_DEVICETREE_IMG4_PATH" || echo "N/A" )
    local rd_bn=$( [[ -n "$FINAL_RAMDISK_IMG4_PATH" ]] && basename "$FINAL_RAMDISK_IMG4_PATH" || echo "N/A" )
    local tc_bn=$( [[ -n "$FINAL_TRUSTCACHE_IMG4_PATH" ]] && basename "$FINAL_TRUSTCACHE_IMG4_PATH" || echo "N/A" )
    local bl_bn=$( [[ -n "$FINAL_BOOTLOGO_IMG4_PATH" ]] && basename "$FINAL_BOOTLOGO_IMG4_PATH" || echo "N/A" )

    cat > "$info_file_path" << EOF
iOS Version: $arg_ios_version
Device Model: $DEVICE_MODEL_RAW
Device CPID: $DEVICE_CPID
Creation Date: $timestamp
Script Version: $SCRIPT_VERSION
Notes: Ramdisk created by iosramdisk.sh. All components are relative to this directory.

Components:
  iBSS: $ibss_bn
  iBEC: $ibec_bn
  KernelCache: $kc_bn
  DeviceTree: $dt_bn
  Ramdisk: $rd_bn
  TrustCache: $tc_bn
  BootLogo: $bl_bn
EOF
    if [[ $? -ne 0 ]]; then
        log_error "Failed to create info.txt at $info_file_path."
    fi

    log_info "Ramdisk creation complete. Output saved to: $current_ramdisk_output_subdir"
    log_info "The working directory $CURRENT_TASK_WORK_DIR will be removed by cleanup trap."
}

boot_ramdisk() {
    local custom_ramdisk_path="$1"
    local selected_ramdisk_path=""

    if [[ -n "$custom_ramdisk_path" ]]; then
        log_info "Custom ramdisk path provided: $custom_ramdisk_path"
        if [[ ! -d "$custom_ramdisk_path" ]]; then
            log_error "Provided ramdisk path '$custom_ramdisk_path' is not a directory."
        fi
        if [[ "$custom_ramdisk_path" != /* ]]; then
            custom_ramdisk_path="$PWD/$custom_ramdisk_path"
        fi
        if [[ ! -f "${custom_ramdisk_path}/info.txt" ]]; then
            log_error "Provided ramdisk path '$custom_ramdisk_path' does not contain an info.txt file."
        fi
        selected_ramdisk_path=$(cd "$custom_ramdisk_path"; pwd)
    else
        log_info "No custom ramdisk path provided. Attempting to find the latest ramdisk in $OUTPUT_DIR..."
        if [[ ! -d "$OUTPUT_DIR" || -z "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]]; then
            log_error "No ramdisks found in '$OUTPUT_DIR'. Please create one first or provide a path."
        fi

        local latest_dir_name=$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d -printf "%T@ %p\n" | sort -nr | head -n1 | cut -d' ' -f2-)
        if [[ -z "$latest_dir_name" ]]; then
            log_error "Could not find any ramdisk directories in $OUTPUT_DIR."
        fi
        selected_ramdisk_path="$latest_dir_name"
        log_info "Attempting to boot latest ramdisk: $selected_ramdisk_path"

        if [[ ! -d "$selected_ramdisk_path" ]]; then
            log_error "Latest ramdisk path '$selected_ramdisk_path' is not a directory."
        fi
        if [[ ! -f "${selected_ramdisk_path}/info.txt" ]]; then
            log_error "Latest ramdisk '$selected_ramdisk_path' does not contain an info.txt. It might be corrupted or incomplete."
        fi
    fi

    log_info "Preparing to boot ramdisk. Custom options will be prioritized."
    log_debug "Custom iBSS (-k): $OPT_CUSTOM_IBSS_PATH"
    log_debug "Custom Kernel (-K): $OPT_CUSTOM_KERNEL_PATH"
    log_debug "Custom Ramdisk (-R): $OPT_CUSTOM_RAMDISK_PATH"
    log_debug "Custom Boot Args (-b): $OPT_BOOT_ARGS"
    log_debug "Custom UDID (-u): $OPT_DEVICE_UDID" # Informational
    log_debug "Custom Overlay (-O): $OPT_CUSTOM_OVERLAY_PATH" # Informational

    ensure_dfu_mode
    pwn_device

    # Determine component paths, prioritizing custom options provided via command-line flags.
    # If a custom path global variable (e.g., OPT_CUSTOM_IBSS_PATH) is set, use that path.
    # Otherwise, fall back to the default path within the selected_ramdisk_path directory.
    local ibss_to_send="${OPT_CUSTOM_IBSS_PATH:-${selected_ramdisk_path}/iBSS.img4}"
    # Default iBEC from the selected ramdisk set. A specific custom iBEC option could be added later if needed.
    local ibec_to_send="${selected_ramdisk_path}/iBEC.img4"
    local kernelcache_to_send="${OPT_CUSTOM_KERNEL_PATH:-${selected_ramdisk_path}/kernelcache.img4}"
    # DeviceTree currently always comes from the selected ramdisk set.
    local devicetree_to_send="${selected_ramdisk_path}/devicetree.img4"
    local ramdisk_to_send="${OPT_CUSTOM_RAMDISK_PATH:-${selected_ramdisk_path}/ramdisk.img4}"
    # Logo currently always comes from the selected ramdisk set.
    local logo_to_send="${selected_ramdisk_path}/logo.img4"
    # TrustCache currently always comes from the selected ramdisk set.
    local trustcache_to_send="${selected_ramdisk_path}/trustcache.img4"

    # Check and warn about boot arguments (-b) usage
    if [[ -n "$OPT_BOOT_ARGS" ]]; then
        if [[ -z "$OPT_CUSTOM_IBSS_PATH" ]]; then # If not using -k (custom iBSS/Pongo)
            log_warn "Boot arguments (-b '$OPT_BOOT_ARGS') were provided without a custom iBSS/PongoOS (-k)."
            log_warn "These arguments are typically effective when patched into an iBEC during its creation process, or if using a custom bootloader (via -k) that accepts runtime arguments (e.g., PongoOS)."
            log_warn "Using -b with default iBEC from '$selected_ramdisk_path' might not have the intended effect, as its boot arguments are pre-set."
        else
            # This case (using -b with -k) is handled later when attempting to send boot-args after the -k file.
            log_debug "Boot arguments (-b '$OPT_BOOT_ARGS') provided. Will attempt to send them after the custom iBSS/PongoOS specified by -k is loaded."
        fi
    fi

    if [[ -n "$OPT_DEVICE_UDID" ]]; then
        log_info "Device UDID (-u) was specified: $OPT_DEVICE_UDID. Note: underlying tools like irecovery may not support targeting specific UDIDs."
    fi

    if [[ -n "$OPT_CUSTOM_OVERLAY_PATH" ]]; then
        log_info "Custom Overlay (-O) was specified: $OPT_CUSTOM_OVERLAY_PATH. Note: This script does not currently process overlays. This option is informational."
    fi

    log_info "Resolved iBSS to send: $ibss_to_send"
    log_info "Resolved iBEC to send: $ibec_to_send"
    log_info "Resolved KernelCache to send: $kernelcache_to_send"
    log_info "Resolved Ramdisk to send: $ramdisk_to_send"

    # Check file existence for all resolved paths before attempting to send.
    # This ensures that whether a default or custom path was chosen, the file is accessible.
    for component_file_var in ibss_to_send ibec_to_send kernelcache_to_send devicetree_to_send ramdisk_to_send; do
        local component_path="${!component_file_var}"
        if [[ ! -f "$component_path" ]]; then
            if [[ ( "$component_file_var" == "ibss_to_send" && -n "$OPT_CUSTOM_IBSS_PATH" ) || \
                  ( "$component_file_var" == "kernelcache_to_send" && -n "$OPT_CUSTOM_KERNEL_PATH" ) || \
                  ( "$component_file_var" == "ramdisk_to_send" && -n "$OPT_CUSTOM_RAMDISK_PATH" ) ]]; then
                log_error "Custom component file for $component_file_var not found at: $component_path"
            else
                log_error "Essential boot component $(basename "$component_path") (derived for $component_file_var) not found in $selected_ramdisk_path or as custom path."
            fi
        fi
    done
    log_info "All essential boot components found at their resolved paths."

    # Determine the correct term for logging based on whether -k is used
    local ibss_log_term="iBSS"
    if [[ -n "$OPT_CUSTOM_IBSS_PATH" ]]; then
        ibss_log_term="iBSS/PongoOS (-k)"
    fi

    log_info "Sending $ibss_log_term: $(basename "$ibss_to_send")..."
    "$IRECOVERY_BIN" -f "$ibss_to_send" || log_error "Failed to send $ibss_log_term ($ibss_to_send)."
    sleep 2 # Allow time for iBSS/PongoOS to load

    # If a custom iBSS/PongoOS is provided via -k, assume it handles iBEC's role.
    # Also, attempt to send boot arguments if provided with -b.
    if [[ -n "$OPT_CUSTOM_IBSS_PATH" ]]; then
        if [[ -n "$OPT_BOOT_ARGS" ]]; then
            log_info "Attempting to send boot-args '$OPT_BOOT_ARGS' to custom $ibss_log_term"
            # This is a speculative attempt. The custom bootloader specified by -k (e.g., PongoOS)
            # might require boot arguments to be passed via a specific irecovery command like 'setenv boot-args'.
            # This behavior is not standardized and depends on the bootloader itself.
            # Alternatively, boot arguments might be patched directly into the custom iBSS/PongoOS file,
            # in which case these commands might be unnecessary or ignored.
            "$IRECOVERY_BIN" -c "setenv boot-args $OPT_BOOT_ARGS" || log_warn "Failed to set boot-args via irecovery command. The custom bootloader (-k) might not support this, or args are already patched."
            "$IRECOVERY_BIN" -c "saveenv" || log_warn "Failed to saveenv for boot-args."
            sleep 1 # Short pause after sending boot-args
        fi
        log_info "Skipping separate iBEC send as custom $ibss_log_term was provided."
        # Skip A10+ "go" command as PongoOS (or custom iBSS) should handle it.
    else
        # Standard flow: Send iBEC if no custom iBSS/PongoOS was provided
        log_info "Sending iBEC: $(basename "$ibec_to_send")..."
        "$IRECOVERY_BIN" -f "$ibec_to_send" || log_error "Failed to send iBEC ($ibec_to_send)."
        # Note: If OPT_BOOT_ARGS were for a *standard* iBEC, they should have been patched in during creation.
        # The warning for this is handled by the logic refined in Step 1.
        sleep 3

        # Conditional 'go' command for A10+ (only if not using custom iBSS/PongoOS)
        case "$DEVICE_CPID" in
            "8010"|"8011"|"8012"|"8015")
                log_info "Device CPID $DEVICE_CPID is A10+. Executing 'go' command..."
                "$IRECOVERY_BIN" -c "go" || log_error "Failed to execute 'go' command for A10+ device."
                sleep 2
                ;;
        esac
    fi

    log_debug "Pausing briefly before sending further components..."
    sleep 2

    if [[ -f "$logo_to_send" ]]; then
        log_info "Sending Boot Logo: $(basename "$logo_to_send")..."
        "$IRECOVERY_BIN" -f "$logo_to_send" || log_warn "Failed to send Boot Logo ($logo_to_send). Continuing..."
        "$IRECOVERY_BIN" -c "setpicture 0x1" || log_warn "Failed to set picture for boot logo. Continuing..."
    else
        log_info "No Boot Logo resolved or found to send. Skipping."
    fi

    log_info "Sending Ramdisk: $(basename "$ramdisk_to_send")..."
    "$IRECOVERY_BIN" -f "$ramdisk_to_send" || log_error "Failed to send Ramdisk ($ramdisk_to_send)."
    "$IRECOVERY_BIN" -c "ramdisk" || log_error "Failed to issue ramdisk command."

    log_info "Sending DeviceTree: $(basename "$devicetree_to_send")..."
    "$IRECOVERY_BIN" -f "$devicetree_to_send" || log_error "Failed to send DeviceTree ($devicetree_to_send)."
    "$IRECOVERY_BIN" -c "devicetree" || log_error "Failed to issue devicetree command."

    if [[ -f "$trustcache_to_send" ]]; then
        log_info "Sending TrustCache: $(basename "$trustcache_to_send")..."
        "$IRECOVERY_BIN" -f "$trustcache_to_send" || log_warn "Failed to send TrustCache ($trustcache_to_send). Continuing..."
        "$IRECOVERY_BIN" -c "firmware" || log_warn "Failed to issue firmware (trustcache) command. Continuing..."
    else
        log_info "No TrustCache resolved or found to send. Skipping."
    fi

    log_info "Sending KernelCache: $(basename "$kernelcache_to_send")..."
    "$IRECOVERY_BIN" -f "$kernelcache_to_send" || log_error "Failed to send KernelCache ($kernelcache_to_send)."

    log_info "Booting device..."
    "$IRECOVERY_BIN" -c "bootx" || log_error "Failed to issue bootx command."

    log_info "Boot commands sent. Device should be booting."
}

# --- Utility Functions ---

connect_ssh() {
    log_info "Attempting to establish SSH connection to device..."

    if [[ -z "$IPROXY_BIN" ]]; then
        log_error "iproxy binary path (IPROXY_BIN) is not set. Cannot establish SSH tunnel."
    fi
    if [[ -z "$SSHPASS_BIN" ]]; then
        log_error "sshpass binary path (SSHPASS_BIN) is not set. Cannot automate SSH password."
    fi

    local iproxy_pid=""

    cleanup_iproxy() {
        if [[ -n "$iproxy_pid" ]]; then
            log_debug "Cleaning up iproxy (PID: $iproxy_pid)..."
            if kill -TERM -$iproxy_pid 2>/dev/null || kill -KILL -$iproxy_pid 2>/dev/null ; then
                 log_debug "Sent TERM or KILL signal to iproxy process group $iproxy_pid."
            fi

            for _ in {1..5}; do
                if ! ps -p $iproxy_pid > /dev/null; then
                    log_debug "iproxy (original PID: $iproxy_pid) terminated."
                    iproxy_pid=""
                    break
                fi
                sleep 0.1
            done

            if [[ -n "$iproxy_pid" ]]; then
                 log_warn "iproxy (PID: $iproxy_pid) may not have terminated cleanly. Manual check might be needed."
            fi
            iproxy_pid=""
        fi
    }
    trap cleanup_iproxy EXIT ERR INT TERM

    log_info "Starting iproxy: mapping local port 2222 to device port 22..."
    set -m
    "$IPROXY_BIN" 2222 22 &
    iproxy_pid=$!
    set +m

    log_debug "iproxy started with PID: $iproxy_pid."

    sleep 2

    if ! ps -p $iproxy_pid > /dev/null; then
        log_error "iproxy failed to start or terminated prematurely. Cannot connect SSH."
        cleanup_iproxy
        trap - EXIT ERR INT TERM
        return 1
    fi

    log_info "Attempting SSH connection to root@localhost:2222 (password: alpine)..."
    "$SSHPASS_BIN" -p 'alpine' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -o LogLevel=ERROR -p 2222 root@localhost

    local ssh_exit_code=$?
    if [[ $ssh_exit_code -ne 0 ]]; then
        if [[ $ssh_exit_code -eq 130 ]]; then
            log_info "SSH session terminated by user (Ctrl+C)."
        else
            log_warn "SSH connection failed or was terminated (exit code: $ssh_exit_code)."
        fi
    else
        log_info "SSH session ended."
    fi

    cleanup_iproxy
    trap - EXIT ERR INT TERM
    log_info "iproxy stopped."
}

clean_output() {
    log_info "Preparing to clean output directory: $OUTPUT_DIR"

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log_info "Output directory '$OUTPUT_DIR' does not exist. Nothing to clean."
        return 0
    fi

    if [ -z "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]; then
       log_info "Output directory '$OUTPUT_DIR' is already empty."
       return 0
    fi

    local confirmation=""
    if [[ -t 0 ]]; then
        read -r -p "Are you sure you want to REMOVE ALL contents of '$OUTPUT_DIR'? This cannot be undone. (yes/no): " confirmation
    else
        log_warn "Cannot read from stdin (not a TTY for clean confirmation). Assuming 'no' for safety."
        confirmation="no"
    fi

    confirmation=$(echo "$confirmation" | tr '[:upper:]' '[:lower:]')

    if [[ "$confirmation" == "yes" ]]; then
        log_info "DELETING contents of '$OUTPUT_DIR'..."
        rm -rf "${OUTPUT_DIR}/"*
        if [[ $? -ne 0 ]]; then
            log_error "Failed to delete contents of '$OUTPUT_DIR'. Check permissions or if files are in use."
        else
            log_info "Output directory '$OUTPUT_DIR' cleaned successfully."
        fi
    else
        log_info "Clean operation cancelled by user or non-interactive environment."
    fi
}


# Call main function with all script arguments
main "$@"
