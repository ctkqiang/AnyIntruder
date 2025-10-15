#include "unity.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct _Unity UnityGlobal;
const char* Unity_TestFunction;

static void UnityInit(void) {
    UnityGlobal.TestFile = NULL;
    UnityGlobal.CurrentTestName = NULL;
    UnityGlobal.NumberOfTests = 0;
    UnityGlobal.TestFailures = 0;
    UnityGlobal.TestIgnores = 0;
}

void UnityBegin(const char* filename) {
    UnityInit();
    UnityGlobal.TestFile = filename;
    UNITY_OUTPUT_START();
}

int UnityEnd(void) {
    UNITY_OUTPUT_COMPLETE();
    printf("Tests Run: %d\n", UnityGlobal.NumberOfTests);
    printf("Failures: %d\n", UnityGlobal.TestFailures);
    printf("Ignores: %d\n", UnityGlobal.TestIgnores);
    return UnityGlobal.TestFailures;
}

void UnityDefaultTestRun(void) {
    UnityGlobal.NumberOfTests++;
}

void UnityPrint(const char* string) {
    UNITY_OUTPUT_CHAR('[');
    while (*string != '\0') {
        UNITY_OUTPUT_CHAR(*string++);
    }
    UNITY_OUTPUT_CHAR(']');
}

void UnityPrintNumber(const unsigned int number) {
    if (number == 0) {
        UNITY_OUTPUT_CHAR('0');
        return;
    }
    char buffer[10];
    int i = 0;
    unsigned int temp = number;
    while (temp > 0) {
        buffer[i++] = (temp % 10) + '0';
        temp /= 10;
    }
    while (i > 0) {
        UNITY_OUTPUT_CHAR(buffer[--i]);
    }
}

void UnityPrintNumberHex(const unsigned int number, const char nibbles_to_print) {
    UNITY_OUTPUT_CHAR('0');
    UNITY_OUTPUT_CHAR('x');
    char nibble;
    int i = nibbles_to_print;
    while (i > 0) {
        i--;
        nibble = (char)((number >> (i * 4)) & 0x0F);
        if (nibble < 10) {
            UNITY_OUTPUT_CHAR((char)('0' + nibble));
        } else {
            UNITY_OUTPUT_CHAR((char)('A' + nibble - 10));
        }
    }
}

void UnityPrintMask(const unsigned int mask, const unsigned int number) {
    UnityPrintNumberHex(mask, 8);
    UNITY_OUTPUT_CHAR(':');
    UnityPrintNumberHex(number, 8);
}

void UnityTestResultsBegin(const char* file, const unsigned int line) {
    UnityPrint(file);
    printf(":%u:FAIL:", line);
}

void UnityTestResultsFailBegin(const unsigned int line) {
    UnityGlobal.TestFailures++;
    UnityTestResultsBegin(UnityGlobal.TestFile, line);
}

void UnityAddMsgIfSpecified(const char* msg) {
    if (msg) {
        UNITY_OUTPUT_CHAR(':');
        UnityPrint(msg);
    }
}

void UnityFailureMessage(void) {
    UNITY_OUTPUT_CHAR('\n');
}

void UnityFinish(void) {
    
}

void UnityPrintF(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}