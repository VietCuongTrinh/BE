#ifndef BE_LSS_H
#define BE_LSS_H

/********************************************************************
*
*   lss.h
*
*   Linear Secret Sharing Scheme
*
*   Appendix G
*
********************************************************************/

#include "config.h"
#include "types.h"
#include "ecc.h"

#include <memory>
#include <vector>
#include <string>
#include <queue>

namespace BE
{

/*==============================================================
    Token
==============================================================*/

enum class TokenType
{
    ATTRIBUTE,

    AND,

    OR,

    LPAREN,

    RPAREN,

    END
};

struct Token
{
    TokenType type;

    std::string text;
};

/*==============================================================
    Lexer
==============================================================*/

class Lexer
{
public:

    explicit Lexer(
        const std::string& policy);

    std::vector<Token> Tokenize();

private:

    std::string input_;

    size_t position_;

    char Peek() const;

    char Get();

    void SkipWhiteSpace();

    Token ReadWord();
};

/*==============================================================
    Access Tree
==============================================================*/

enum class NodeType
{
    ATTRIBUTE,

    AND,

    OR
};

struct AccessNode
{
    NodeType type;

    std::string attribute;

    std::shared_ptr<AccessNode> left;

    std::shared_ptr<AccessNode> right;

    int row;

    AccessNode();

    bool IsLeaf() const;
};

/*==============================================================
    Parser
==============================================================*/

class Parser
{
public:

    explicit Parser(
        const std::vector<Token>& tokens);

    std::shared_ptr<AccessNode>
    Parse();

private:

    std::vector<Token> tokens_;

    size_t current_;

    const Token& Peek() const;

    const Token& Previous() const;

    bool Match(TokenType type);

    std::shared_ptr<AccessNode> Expression();

    std::shared_ptr<AccessNode> OrExpression();

    std::shared_ptr<AccessNode> AndExpression();

    std::shared_ptr<AccessNode> Primary();
};

/*==============================================================
    LSS Generator
==============================================================*/

class LSSGenerator
{
public:

    explicit LSSGenerator(
        const ECCContext& ecc);

    bool Generate(
        const std::string& policy,
        LSSMatrix& matrix);

private:

    const ECCContext& ecc_;

    void BuildMatrix(
            const std::shared_ptr<AccessNode>& root,
            std::vector<int> vector,
            int columns,
            LSSMatrix& matrix);

    void ExpandAND(
            std::vector<int>& left,
            std::vector<int>& right,
            int columns);

    void ExpandOR(
            std::vector<int>& left,
            std::vector<int>& right);

    void NumberLeaves(
            const std::shared_ptr<AccessNode>& root,
            int& counter);
};

/*==============================================================
    Secret Sharing
==============================================================*/

bool GenerateShares(
        const ECCContext& ecc,
        const LSSMatrix& matrix,
        const BIGNUM* secret,
        std::vector<BN_ptr>& lambda);

/*==============================================================
    Reconstruction
==============================================================*/

bool ReconstructionCoefficients(
        const ECCContext& ecc,
        const LSSMatrix& matrix,
        const std::vector<int>& rows,
        std::vector<BN_ptr>& beta);

/*==============================================================
    Utility
==============================================================*/

bool ParsePolicy(
        const std::string& policy,
        std::shared_ptr<AccessNode>& root);

bool PolicySatisfied(
        const std::shared_ptr<AccessNode>& root,
        const std::vector<std::string>& attributes);

std::vector<std::string>
ExtractAttributes(
        const std::shared_ptr<AccessNode>& root);

void PrintTree(
        const std::shared_ptr<AccessNode>& root,
        int depth = 0);

} // namespace BE

#endif