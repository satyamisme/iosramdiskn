#include <Achilles.h>
#include <exploit/exploit.h>
#include <pongo/pongoterm.h>

char *get_argument_value(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            if (i+1 < argc) {
                return argv[i+1];
            }
        }
    }
    return NULL;
}

bool argument_exists(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            if (!strcmp(flag, "-v") && (i - 1 > 0) && !strcmp(argv[i - 1], "-b")) { // -v is a valid boot argument
                return false;
            }
            return true;
        }
    }
    return false;
}

void display_dfu_command_examples(char *executablePath) {
    printf("\n----------------------------------------------------------------------\n");
    printf("DFU Device Detected! Here are some common command examples:\n");
    printf("----------------------------------------------------------------------\n\n");

    printf("Tip: Organize your PongoOS files (e.g., Pongo.bin, checkra1n-kpf-pongo, ramdisk.dmg) in a known location.\n");
    printf("For example, create a directory like './pongo_files/'\n\n");

    printf("1. Boot PongoOS (minimal, using default PongoOS if available or specify with -k):\n");
    printf("   %s -p\n", executablePath);
    printf("   %s -p -k ./pongo_files/Pongo.bin\n\n", executablePath);

    printf("2. Jailbreak with a Kernel Patch Finder (KPF), Ramdisk, and Overlay:\n");
    printf("   (Replace file names with your actual files)\n");
    printf("   %s -j -K ./pongo_files/checkra1n-kpf-pongo -R ./pongo_files/ramdisk.dmg -O ./pongo_files/overlay.dmg\n\n", executablePath);

    printf("3. Boot a custom Ramdisk and Overlay (without full jailbreak, e.g., for custom tools):\n");
    printf("   %s -K ./pongo_files/checkra1n-kpf-pongo -R ./pongo_files/rootedramdisk.dmg -O ./pongo_files/overlay.dmg\n", executablePath);
    printf("   (Note: '-K' might be needed if the ramdisk requires a patched kernel to boot)\n\n");

    printf("4. Boot PongoOS with specific boot arguments:\n");
    printf("   %s -p -b \"example_arg=1 another_arg=test\"\n\n", executablePath);

    printf("5. Use a specific PongoOS image and then start a PongoOS shell:\n");
    printf("   %s -T -k ./pongo_files/PongoConsolidated.bin\n\n", executablePath);

    printf("6. Remove signature checks (if supported by the exploit for your device):\n");
    printf("   %s -s\n\n", executablePath);

    printf("Remember to replace placeholder paths like './pongo_files/' and filenames with your actual file paths.\n");
    printf("You can also specify a device by UDID using the -u <UDID> option if multiple devices are connected.\n");
    printf("----------------------------------------------------------------------\n\n");
}

void print_usage(char *executablePath) {
    printf("Options:\n");
    printf("\t-d - enable debug logging\n");
    printf("\t-v - enable verbose logging\n");
    printf("\t-q - enable quiet logging (removes all logging except for errors)\n");
    printf("\t-s - remove signature checks\n");
    printf("\t-p - boot to PongoOS and exit\n");
    printf("\t-j - jailbreak the device (requires -K)\n");
    printf("\t-V - enable verbose boot\n");
    printf("\t-S - enable serial output\n");
    printf("\t-T - start a PongoOS shell\n\n");
    printf("\t-u <UDID> - specify a device UDID\n");
    printf("\t-b <arguments> - additional boot arguments\n");
    printf("\t-k <Pongo.bin> - override PongoOS image\n");
    printf("\t-K <kpf> - override kernel patchfinder\n");
    printf("\t-R <ramdisk.dmg> - ramdisk to boot\n");
    printf("\t-O <overlay.dmg> - overlay to boot\n\n");
    printf("\t-h - print this help message\n");
    printf("Examples:\n");
    printf("\t%s -p\n", executablePath);
    printf("\t%s -j -K kpf -R ramdisk.dmg -O overlay.dmg\n", executablePath);
    printf("\t%s -s\n", executablePath);
    exit(-1);
}

struct AchillesArgs args;

bool check_for_argument_conflicts(struct AchillesArgs args, char *argv0) {
    if (args.jailbreak && !args.kpfPath) {
        LOG(LOG_ERROR, "-j requires -K.");
        print_usage(argv0);
        return false;
    }

    if (args.bootToPongo && args.jailbreak) {
        LOG(LOG_ERROR, "-p and -j are mutually exclusive.");
        print_usage(argv0);
        return false;
    }

    if (!args.disableSignatureChecks && !args.bootToPongo && !args.jailbreak && !args.pongoterm) {
        LOG(LOG_ERROR, "You must specify either -s, -p, or -j.");
        print_usage(argv0);
        return false;
    }

    if (args.disableSignatureChecks && (args.bootToPongo || args.jailbreak)) {
        LOG(LOG_ERROR, "-s is incompatible with -p and -j.");
        print_usage(argv0);
        return false;
    }
    return true;
}

struct AchillesArgs args;

bool check_custom_paths(struct AchillesArgs args) {
    struct stat st;
    if (args.pongoPath) {
        if (stat(args.pongoPath, &st) != 0) {
            LOG(LOG_ERROR, "PongoOS image at %s does not exist.", args.pongoPath);
            return false;
        }
    }

    if (args.kpfPath) {
        if (stat(args.kpfPath, &st) != 0) {
            LOG(LOG_ERROR, "Kernel patchfinder at %s does not exist", args.kpfPath);
            return false;
        }
    }

    if (args.ramdiskPath) {
        if (stat(args.ramdiskPath, &st) != 0) {
            LOG(LOG_ERROR, "Ramdisk at %s does not exist.", args.ramdiskPath);
            return false;
        }
    }

    if (args.overlayPath) {
        if (stat(args.overlayPath, &st) != 0) {
            LOG(LOG_ERROR, "Overlay at %s does not exist.", args.overlayPath);
            return false;
        }
    }
    return true;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        print_usage(argv[0]);
    }

    args.deviceUDID = get_argument_value(argc, argv, "-u");
    
    args.debug = argument_exists(argc, argv, "-d");
    args.verbose = argument_exists(argc, argv, "-v");
    args.quiet = argument_exists(argc, argv, "-q");
    args.disableSignatureChecks = argument_exists(argc, argv, "-s");
    args.bootToPongo = argument_exists(argc, argv, "-p");
    args.jailbreak = argument_exists(argc, argv, "-j");
    args.verboseBoot = argument_exists(argc, argv, "-V");
    args.serialOutput = argument_exists(argc, argv, "-S");
    args.bootArgs = get_argument_value(argc, argv, "-b");
    args.pongoterm = argument_exists(argc, argv, "-T");

    args.pongoPath = get_argument_value(argc, argv, "-k");
    args.kpfPath = get_argument_value(argc, argv, "-K");
    args.ramdiskPath = get_argument_value(argc, argv, "-R");
    args.overlayPath = get_argument_value(argc, argv, "-O");

    if (argument_exists(argc, argv, "-h")) {
        print_usage(argv[0]);
    }

    if (!check_for_argument_conflicts(args, argv[0])) {
        return -1;
    }
    
    if (!check_custom_paths(args)) {
        return -1;
    }

    if (args.pongoterm) {
        pongoterm();
    } else {
        checkm8((args.bootToPongo || args.jailbreak) ? MODE_PONGOOS : MODE_CHECKM8, argv[0]);
    }

    return 0;
}