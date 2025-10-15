#include "unity.h"
#include "../includes/webhook/dingding.h"
#include "../includes/webhook/discord.h"
#include "../includes/webhook/telegram.h"
#include "../includes/webhook/wechat.h"
#include <string.h>

static DING_DING dingding;
static Discord discord;
static WeChat wechat;
static const char* test_webhook_url = "https://test.webhook.url";
static const char* test_message = "Test message";

void setUp(void) {
    memset(&dingding, 0, sizeof(DING_DING));
    memset(&discord, 0, sizeof(Discord));
    memset(&wechat, 0, sizeof(WeChat));
}

void tearDown(void) {}

void test_dingding_bot_init(void) {
    TEST_ASSERT_EQUAL_INT(0x0, dingding_init(&dingding));
    TEST_ASSERT_NOT_NULL(dingding.DINDING_ACCESS_TOKEN);
    TEST_ASSERT_NOT_NULL(dingding.DINGDING_SECRET);
}

void test_dingding_bot_init_null_params(void) {
    TEST_ASSERT_NOT_EQUAL(0x0, dingding_init(NULL));
}

void test_discord_bot_init(void) {
    TEST_ASSERT_EQUAL_INT(0x0, discord_bot_init(&discord, test_webhook_url));
    TEST_ASSERT_NOT_NULL(discord.webhook_url);
    TEST_ASSERT_EQUAL_STRING(test_webhook_url, discord.webhook_url);
}

void test_discord_bot_init_null_params(void) {
    TEST_ASSERT_NOT_EQUAL(0x0, discord_bot_init(NULL, test_webhook_url));
    TEST_ASSERT_NOT_EQUAL(0x0, discord_bot_init(&discord, NULL));
}

void test_wechat_bot_init(void) {
    TEST_ASSERT_EQUAL_INT(0x0, wechat_bot_init(&wechat, test_webhook_url));
    TEST_ASSERT_NOT_NULL(wechat.webhook_url);
    TEST_ASSERT_EQUAL_STRING(test_webhook_url, wechat.webhook_url);
}

void test_wechat_bot_init_null_params(void) {
    TEST_ASSERT_NOT_EQUAL(0x0, wechat_bot_init(NULL, test_webhook_url));
    TEST_ASSERT_NOT_EQUAL(0x0, wechat_bot_init(&wechat, NULL));
}

int main(void) {
    UnityBegin("test_webhook.c");
    RUN_TEST(test_dingding_bot_init);
    RUN_TEST(test_dingding_bot_init_null_params);
    RUN_TEST(test_discord_bot_init);
    RUN_TEST(test_discord_bot_init_null_params);
    RUN_TEST(test_wechat_bot_init);
    RUN_TEST(test_wechat_bot_init_null_params);
    return UnityEnd();
}