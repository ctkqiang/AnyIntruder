#ifndef UNITY_FRAMEWORK_H
#define UNITY_FRAMEWORK_H

#define UNITY_INCLUDE_SETUP_STUBS
#define UNITY_INT_WIDTH (32)
#define UNITY_DISPLAY_STYLE_INT (0)

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#define UNITY_OUTPUT_CHAR(a) putchar(a)
#define UNITY_OUTPUT_START() printf("\n\n-----------------\n")
#define UNITY_OUTPUT_COMPLETE() printf("\n-----------------\n\n")

extern int Unity_Counter;
extern const char* Unity_TestFunction;

void UnityBegin(const char* filename);
extern int UnityEnd(void);
void UnityDefaultTestRun(void);
void UnityPrint(const char* string);
void UnityPrintNumber(const unsigned int number);
void UnityPrintNumberHex(const unsigned int number, const char nibbles_to_print);
void UnityPrintMask(const unsigned int mask, const unsigned int number);
void UnityTestResultsBegin(const char* file, const unsigned int line);
void UnityTestResultsFailBegin(const unsigned int line);
void UnityAddMsgIfSpecified(const char* msg);
void UnityFailureMessage(void);
void UnityFinish(void);
void UnityPrintF(const char* format, ...);

#define TEST_PROTECT() (setjmp(Unity.AbortFrame) == 0)
#define TEST_ABORT() longjmp(Unity.AbortFrame, 1)

#define TEST_ASSERT_MESSAGE(condition, message) do { if (!(condition)) { UnityTestResultsFailBegin(__LINE__); UnityPrint(message); UnityFailureMessage(); }} while (0)
#define TEST_ASSERT(condition) TEST_ASSERT_MESSAGE(condition, #condition " is false")
#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition)
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition))
#define TEST_ASSERT_NULL(pointer) TEST_ASSERT_MESSAGE(pointer == NULL, #pointer " is not NULL")
#define TEST_ASSERT_NOT_NULL(pointer) TEST_ASSERT_MESSAGE(pointer != NULL, #pointer " is NULL")
#define TEST_ASSERT_EQUAL_INT(expected, actual) TEST_ASSERT_MESSAGE((expected) == (actual), "Expected " #expected " was " #actual)
#define TEST_ASSERT_NOT_EQUAL(expected, actual) TEST_ASSERT_MESSAGE((expected) != (actual), "Expected " #expected " was not " #actual)
#define TEST_ASSERT_EQUAL_STRING(expected, actual) TEST_ASSERT_MESSAGE(strcmp(expected, actual) == 0, "Strings not equal")

#define RUN_TEST(func) do { Unity_TestFunction = #func; func(); } while (0)

typedef struct _Unity Unity;
typedef void (*UnityTestFunction)(void);

struct _Unity {
    const char* TestFile;
    const char* CurrentTestName;
    int NumberOfTests;
    int TestFailures;
    int TestIgnores;
    jmp_buf AbortFrame;
};

extern struct _Unity UnityGlobal;

#endif