// Leaks are not the defect class this fleet fuzzes for; keep ASan/UBSan, turn LeakSanitizer off.
extern "C" int __lsan_is_turned_off() { return 1; }
