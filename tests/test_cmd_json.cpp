#include <gtest/gtest.h>
#include "../src/ipmon.h"
#include <jsoncpp/json/json.h>
#include <iostream>

// Helper function to normalize JSON strings by removing whitespace
std::string normalize_json(const std::string& json_str) {
    std::string result;
    result.reserve(json_str.size());
    for (char c : json_str) {
        if (!std::isspace(c)) {
            result += c;
        }
    }
    return result;
}

TEST(CmdJsonTest, BasicCmdJson)
{
    std::cout << "Starting BasicCmdJson test" << std::endl;
    cmd_json root("root");
    Json::Value val;
    val["key"] = "value";
    root.append(val);
    std::cout << "Value appended" << std::endl;
    std::string expected = R"({"root":[{"key":"value"}]})";
    std::cout << "Expected: " << expected << std::endl;
    std::cout << "Actual: " << root.get_str() << std::endl;
    EXPECT_EQ(normalize_json(root.get_str()), normalize_json(expected));
}

TEST(CmdJsonTest, PrettyPrint)
{
    cmd_json root("root");
    Json::Value val;
    val["key"] = "value";
    root.append(val);
    std::string pp = root.get_pp();
    EXPECT_NE(pp.find("key"), std::string::npos);
}

TEST(CmdJsonA_Test, AppendCmd)
{
    cmd_json_a array_cmd("array");
    Json::Value val1;
    val1["cmd"] = "test1";
    array_cmd.cmd_append(val1);
    Json::Value val2;
    val2["cmd"] = "test2";
    array_cmd.cmd_append(val2);
    Json::Value expected;
    expected["array"].append(val1);
    expected["array"].append(val2);
    EXPECT_EQ(normalize_json(array_cmd.get_str()), 
              normalize_json(Json::FastWriter().write(expected)));
}

TEST(ProxySeqTest, BasicProxySeq)
{
    proxy_seq seq;
    Json::Value cmd;
    cmd["command"] = "reload";
    seq.cmd_append(cmd);
    Json::Value expected;
    expected["!seq"].append(cmd);
    EXPECT_EQ(normalize_json(seq.get_str()),
              normalize_json(Json::FastWriter().write(expected)));
}

TEST(NftRootTest, TestCmdAppend)
{
    nft_root nft;
    nft.test_cmd_append("flush set");
    nft.test_cmd_append("add set");
    EXPECT_EQ(nft.test_cmds.size(), 2);
    EXPECT_EQ(nft.test_cmds[0], "flush set");
    EXPECT_EQ(nft.test_cmds[1], "add set");
} 