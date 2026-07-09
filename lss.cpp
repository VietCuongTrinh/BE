/********************************************************************
*
*   lss.cpp
*
*   Linear Secret Sharing Scheme
*
********************************************************************/

#include "lss.h"
#include "util.h"

#include <stack>
#include <queue>
#include <cctype>
#include <iostream>

namespace BE
{

/*==============================================================
    Lexer
==============================================================*/

/*-------------------------------------------------------------
    Constructor
--------------------------------------------------------------*/

Lexer::Lexer(
        const std::string& policy)
    : input_(policy),
      position_(0)
{

}

/*-------------------------------------------------------------
    Peek
--------------------------------------------------------------*/

char Lexer::Peek() const
{
    if(position_ >= input_.length())
        return '\0';

    return input_[position_];
}

/*-------------------------------------------------------------
    Get
--------------------------------------------------------------*/

char Lexer::Get()
{
    if(position_ >= input_.length())
        return '\0';

    return input_[position_++];
}

/*-------------------------------------------------------------
    Skip White Space
--------------------------------------------------------------*/

void Lexer::SkipWhiteSpace()
{
    while(std::isspace(
            static_cast<unsigned char>(Peek())))
    {
        ++position_;
    }
}

/*-------------------------------------------------------------
    Read Identifier
--------------------------------------------------------------*/

Token Lexer::ReadWord()
{
    std::string word;

    while(std::isalnum(
            static_cast<unsigned char>(Peek()))
          ||
          Peek() == '_')
    {
        word.push_back(Get());
    }

    std::string upper =
        ToUpper(word);

    if(upper == "AND")
    {
        return
        {
            TokenType::AND,
            word
        };
    }

    if(upper == "OR")
    {
        return
        {
            TokenType::OR,
            word
        };
    }

    return
    {
        TokenType::ATTRIBUTE,
        word
    };
}

/*-------------------------------------------------------------
    Tokenize
--------------------------------------------------------------*/

std::vector<Token>
Lexer::Tokenize()
{
    std::vector<Token> tokens;

    while(true)
    {
        SkipWhiteSpace();

        char c = Peek();

        if(c == '\0')
            break;

        switch(c)
        {
        case '(':

            Get();

            tokens.push_back(
            {
                TokenType::LPAREN,
                "("
            });

            break;

        case ')':

            Get();

            tokens.push_back(
            {
                TokenType::RPAREN,
                ")"
            });

            break;

        default:

            if(std::isalnum(
                    static_cast<unsigned char>(c))
               ||
               c == '_')
            {
                tokens.push_back(
                        ReadWord());
            }
            else
            {
                /*
                    Ignore illegal character
                */

                Get();
            }

            break;
        }
    }

    tokens.push_back(
    {
        TokenType::END,
        ""
    });

    return tokens;
}

} // namespace BE
/*==============================================================
    AccessNode
==============================================================*/

AccessNode::AccessNode()
    : type(NodeType::ATTRIBUTE),
      row(-1)
{
}

bool AccessNode::IsLeaf() const
{
    return left == nullptr && right == nullptr;
}

/*==============================================================
    Parser
==============================================================*/

/*-------------------------------------------------------------
    Constructor
--------------------------------------------------------------*/

Parser::Parser(
        const std::vector<Token>& tokens)
    : tokens_(tokens),
      current_(0)
{
}

/*-------------------------------------------------------------
    Peek
--------------------------------------------------------------*/

const Token&
Parser::Peek() const
{
    return tokens_[current_];
}

/*-------------------------------------------------------------
    Previous
--------------------------------------------------------------*/

const Token&
Parser::Previous() const
{
    return tokens_[current_-1];
}

/*-------------------------------------------------------------
    Match
--------------------------------------------------------------*/

bool Parser::Match(TokenType type)
{
    if(Peek().type != type)
        return false;

    ++current_;

    return true;
}

/*-------------------------------------------------------------
    Parse
--------------------------------------------------------------*/

std::shared_ptr<AccessNode>
Parser::Parse()
{
    return Expression();
}

/*-------------------------------------------------------------
    Expression

    Lowest precedence
--------------------------------------------------------------*/

std::shared_ptr<AccessNode>
Parser::Expression()
{
    return OrExpression();
}

/*-------------------------------------------------------------
    OR
--------------------------------------------------------------*/

std::shared_ptr<AccessNode>
Parser::OrExpression()
{
    auto node =
        AndExpression();

    while(Match(TokenType::OR))
    {
        auto parent =
            std::make_shared<AccessNode>();

        parent->type =
            NodeType::OR;

        parent->left = node;

        parent->right =
            AndExpression();

        node = parent;
    }

    return node;
}

/*-------------------------------------------------------------
    AND
--------------------------------------------------------------*/

std::shared_ptr<AccessNode>
Parser::AndExpression()
{
    auto node =
        Primary();

    while(Match(TokenType::AND))
    {
        auto parent =
            std::make_shared<AccessNode>();

        parent->type =
            NodeType::AND;

        parent->left = node;

        parent->right =
            Primary();

        node = parent;
    }

    return node;
}

/*-------------------------------------------------------------
    Primary
--------------------------------------------------------------*/

std::shared_ptr<AccessNode>
Parser::Primary()
{
    /*
        (
    */

    if(Match(TokenType::LPAREN))
    {
        auto node =
            Expression();

        if(!Match(TokenType::RPAREN))
        {
            throw std::runtime_error(
                "Missing ')' in access policy.");
        }

        return node;
    }

    /*
        Attribute
    */

    if(Match(TokenType::ATTRIBUTE))
    {
        auto node =
            std::make_shared<AccessNode>();

        node->type =
            NodeType::ATTRIBUTE;

        node->attribute =
            Previous().text;

        return node;
    }

    throw std::runtime_error(
        "Invalid access policy.");
}
/*==============================================================
    Number Leaves
==============================================================*/

void LSSGenerator::NumberLeaves(
        const std::shared_ptr<AccessNode>& node,
        int& counter)
{
    if(node == nullptr)
        return;

    if(node->IsLeaf())
    {
        node->row = counter++;
        return;
    }

    NumberLeaves(node->left, counter);
    NumberLeaves(node->right, counter);
}

/*==============================================================
    Expand OR
==============================================================*/

void LSSGenerator::ExpandOR(
        std::vector<int>& left,
        std::vector<int>& right)
{
    right = left;
}

/*==============================================================
    Expand AND
==============================================================*/

void LSSGenerator::ExpandAND(
        std::vector<int>& left,
        std::vector<int>& right,
        int columns)
{
    left.resize(columns + 1, 0);
    right.resize(columns + 1, 0);

    left[columns]  =  1;
    right[columns] = -1;
}

/*==============================================================
    Build Matrix
==============================================================*/

void LSSGenerator::BuildMatrix(
        const std::shared_ptr<AccessNode>& node,
        std::vector<int> vector,
        int columns,
        LSSMatrix& matrix)
{
    if(node == nullptr)
        return;

    /*
        Leaf node
    */

    if(node->IsLeaf())
    {
        std::vector<BIGNUM*> row;

        row.reserve(vector.size());

        for(int x : vector)
        {
            BIGNUM* bn = BN_new();

            if(x >= 0)
            {
                BN_set_word(
                    bn,
                    static_cast<BN_ULONG>(x));
            }
            else
            {
                /*
                    Store q-|x|
                    (real modular conversion will be
                    completed during secret sharing)
                */

                BN_set_word(
                    bn,
                    static_cast<BN_ULONG>(-x));

                BN_set_negative(
                    bn,
                    1);
            }

            row.push_back(bn);
        }

        matrix.matrix.push_back(
                std::move(row));

        matrix.rho.push_back(
                node->attribute);

        return;
    }

    /*
        OR gate
    */

    if(node->type == NodeType::OR)
    {
        auto leftVector = vector;

        auto rightVector = vector;

        ExpandOR(
            leftVector,
            rightVector);

        BuildMatrix(
            node->left,
            leftVector,
            columns,
            matrix);

        BuildMatrix(
            node->right,
            rightVector,
            columns,
            matrix);

        return;
    }

    /*
        AND gate
    */

    if(node->type == NodeType::AND)
    {
        auto leftVector = vector;

        auto rightVector = vector;

        ExpandAND(
            leftVector,
            rightVector,
            columns);

        BuildMatrix(
            node->left,
            leftVector,
            columns + 1,
            matrix);

        BuildMatrix(
            node->right,
            rightVector,
            columns + 1,
            matrix);

        return;
    }
}
/*==============================================================
    Constructor
==============================================================*/

LSSGenerator::LSSGenerator(
        const ECCContext& ecc)
    : ecc_(ecc)
{

}

/*==============================================================
    Generate LSS Matrix
==============================================================*/

bool LSSGenerator::Generate(
        const std::string& policy,
        LSSMatrix& matrix)
{
    /*
        Clear old matrix
    */

    matrix.Clear();

    /*
        Lexical analysis
    */

    Lexer lexer(policy);

    auto tokens =
        lexer.Tokenize();

    if(tokens.empty())
        return false;

    /*
        Parse
    */

    Parser parser(tokens);

    auto root =
        parser.Parse();

    if(root == nullptr)
        return false;

    /*
        Number leaves
    */

    int counter = 0;

    NumberLeaves(
        root,
        counter);

    /*
        Initial vector

            (1)
    */

    std::vector<int> v(1);

    v[0] = 1;

    /*
        Build (M,rho)
    */

    BuildMatrix(
        root,
        v,
        1,
        matrix);

    /*
        Normalize row length
    */

    size_t maxColumns = 0;

    for(const auto& row : matrix.matrix)
    {
        if(row.size() > maxColumns)
            maxColumns = row.size();
    }

    for(auto& row : matrix.matrix)
    {
        while(row.size() < maxColumns)
        {
            BIGNUM* zero = BN_new();

            BN_zero(zero);

            row.push_back(zero);
        }
    }

    return true;
}

/*==============================================================
    ParsePolicy
==============================================================*/

bool ParsePolicy(
        const std::string& policy,
        std::shared_ptr<AccessNode>& root)
{
    try
    {
        Lexer lexer(policy);

        auto tokens =
            lexer.Tokenize();

        Parser parser(tokens);

        root =
            parser.Parse();

        return root != nullptr;
    }
    catch(...)
    {
        root.reset();

        return false;
    }
}
/*==============================================================
    Secret Sharing
==============================================================*/

/*-------------------------------------------------------------
    Generate Shares
--------------------------------------------------------------*/

bool GenerateShares(
        const ECCContext& ecc,
        const LSSMatrix& matrix,
        const BIGNUM* secret,
        std::vector<BN_ptr>& lambda)
{
    lambda.clear();

    if(secret == nullptr)
        return false;

    if(matrix.matrix.empty())
        return false;

    /*
        Number of columns
    */

    const size_t cols =
        matrix.matrix[0].size();

    /*
        Generate random vector

            v=(s,r2,...,rn)
    */

    std::vector<BN_ptr> v;

    v.reserve(cols);

    /*
        First component = secret
    */

    v.emplace_back(
        BN_dup(secret),
        BN_free);

    /*
        Remaining components
    */

    for(size_t j=1;j<cols;++j)
    {
        v.emplace_back(
            RandomNonZeroScalar(ecc));
    }

    /*
        Compute λi = Mi*v
    */

    lambda.reserve(
        matrix.matrix.size());

    for(const auto& row : matrix.matrix)
    {
        BN_ptr share(
            BN_new(),
            BN_free);

        if(!share)
            return false;

        BN_zero(share.get());

        for(size_t j=0;j<cols;++j)
        {
            BN_ptr coeff(
                BN_dup(row[j]),
                BN_free);

            /*
                Convert negative value
            */

            if(BN_is_negative(coeff.get()))
            {
                BN_set_negative(
                    coeff.get(),
                    0);

                BN_mod_sub(
                    coeff.get(),
                    ecc.Order(),
                    coeff.get(),
                    ecc.Order(),
                    ecc.Context());
            }

            auto product =
                ScalarMul(
                    ecc,
                    coeff.get(),
                    v[j].get());

            auto sum =
                ScalarAdd(
                    ecc,
                    share.get(),
                    product.get());

            share.swap(sum);
        }

        lambda.emplace_back(
            std::move(share));
    }

    return true;
}
/*==============================================================
    Reconstruction Coefficients
==============================================================*/

/*-------------------------------------------------------------
    ReconstructionCoefficients
--------------------------------------------------------------*/

bool ReconstructionCoefficients(
        const ECCContext& ecc,
        const LSSMatrix& matrix,
        const std::vector<int>& rows,
        std::vector<BN_ptr>& beta)
{
    beta.clear();

    if(rows.empty())
        return false;

    if(matrix.matrix.empty())
        return false;

    const size_t n =
        matrix.matrix[0].size();

    const size_t m =
        rows.size();

    /*
        Need at least n rows.
    */

    if(m < n)
        return false;

    /*
        Build augmented matrix
    */

    std::vector<std::vector<BN_ptr>> A;

    A.resize(m);

    for(size_t i = 0; i < m; ++i)
    {
        A[i].resize(n + 1);

        for(size_t j = 0; j < n; ++j)
        {
            A[i][j] =
                CopyScalar(
                    matrix.matrix[rows[i]][j]);
        }

        /*
            Right-hand side

                (1,0,...,0)^T
        */

        if(i == 0)
        {
            A[i][n] =
                CopyScalar(BN_value_one());
        }
        else
        {
            A[i][n].reset(BN_new());
            BN_zero(A[i][n].get());
        }
    }

    /*
        Gaussian Elimination
    */

    for(size_t col = 0; col < n; ++col)
    {
        size_t pivot = col;

        while(pivot < m &&
              BN_is_zero(A[pivot][col].get()))
        {
            ++pivot;
        }

        if(pivot == m)
            return false;

        if(pivot != col)
        {
            std::swap(
                A[pivot],
                A[col]);
        }

        /*
            Normalize pivot row
        */

        auto inv =
            ScalarInverse(
                ecc,
                A[col][col].get());

        if(!inv)
            return false;

        for(size_t j = col; j <= n; ++j)
        {
            A[col][j] =
                ScalarMul(
                    ecc,
                    A[col][j].get(),
                    inv.get());
        }

        /*
            Eliminate
        */

        for(size_t i = 0; i < m; ++i)
        {
            if(i == col)
                continue;

            if(BN_is_zero(A[i][col].get()))
                continue;

            auto factor =
                CopyScalar(
                    A[i][col].get());

            for(size_t j = col; j <= n; ++j)
            {
                auto tmp =
                    ScalarMul(
                        ecc,
                        factor.get(),
                        A[col][j].get());

                auto value =
                    ScalarSub(
                        ecc,
                        A[i][j].get(),
                        tmp.get());

                A[i][j].swap(value);
            }
        }
    }

    /*
        β
    */

    beta.reserve(m);

    for(size_t i = 0; i < m; ++i)
    {
        beta.emplace_back(
            CopyScalar(
                A[i][n].get()));
    }

    return true;
}
/*==============================================================
    Policy Evaluation
==============================================================*/

/*-------------------------------------------------------------
    Contains Attribute
--------------------------------------------------------------*/

static bool ContainsAttribute(
        const std::vector<std::string>& attributes,
        const std::string& target)
{
    return std::find(
                attributes.begin(),
                attributes.end(),
                target)
            != attributes.end();
}

/*-------------------------------------------------------------
    PolicySatisfied
--------------------------------------------------------------*/

bool PolicySatisfied(
        const std::shared_ptr<AccessNode>& root,
        const std::vector<std::string>& attributes)
{
    if(root == nullptr)
        return false;

    /*
        Leaf
    */

    if(root->IsLeaf())
    {
        return ContainsAttribute(
                    attributes,
                    root->attribute);
    }

    /*
        AND
    */

    if(root->type == NodeType::AND)
    {
        return PolicySatisfied(
                    root->left,
                    attributes)
            &&
               PolicySatisfied(
                    root->right,
                    attributes);
    }

    /*
        OR
    */

    if(root->type == NodeType::OR)
    {
        return PolicySatisfied(
                    root->left,
                    attributes)
            ||
               PolicySatisfied(
                    root->right,
                    attributes);
    }

    return false;
}

/*==============================================================
    Extract Attributes
==============================================================*/

static void ExtractAttributesDFS(
        const std::shared_ptr<AccessNode>& node,
        std::vector<std::string>& result)
{
    if(node == nullptr)
        return;

    if(node->IsLeaf())
    {
        result.push_back(
            node->attribute);
        return;
    }

    ExtractAttributesDFS(
            node->left,
            result);

    ExtractAttributesDFS(
            node->right,
            result);
}

/*-------------------------------------------------------------*/

std::vector<std::string>
ExtractAttributes(
        const std::shared_ptr<AccessNode>& root)
{
    std::vector<std::string> result;

    ExtractAttributesDFS(
            root,
            result);

    /*
        Remove duplicates
    */

    std::sort(
        result.begin(),
        result.end());

    result.erase(
        std::unique(
            result.begin(),
            result.end()),
        result.end());

    return result;
}

/*==============================================================
    Collect Leaf Rows
==============================================================*/

static void CollectRows(
        const std::shared_ptr<AccessNode>& node,
        const std::vector<std::string>& attributes,
        std::vector<int>& rows)
{
    if(node == nullptr)
        return;

    if(node->IsLeaf())
    {
        if(ContainsAttribute(
                attributes,
                node->attribute))
        {
            rows.push_back(
                node->row);
        }

        return;
    }

    CollectRows(
            node->left,
            attributes,
            rows);

    CollectRows(
            node->right,
            attributes,
            rows);
}

/*-------------------------------------------------------------*/

std::vector<int>
SatisfiedRows(
        const std::shared_ptr<AccessNode>& root,
        const std::vector<std::string>& attributes)
{
    std::vector<int> rows;

    CollectRows(
            root,
            attributes,
            rows);

    return rows;
}
/*==============================================================
    Minimal Satisfied Set
==============================================================*/

namespace
{

bool FindRowsDFS(
        const std::shared_ptr<AccessNode>& node,
        const std::vector<std::string>& attributes,
        std::vector<int>& rows)
{
    if(node == nullptr)
        return false;

    /*
        Leaf
    */

    if(node->IsLeaf())
    {
        if(std::find(
                attributes.begin(),
                attributes.end(),
                node->attribute)
            != attributes.end())
        {
            rows.push_back(node->row);
            return true;
        }

        return false;
    }

    /*
        AND
    */

    if(node->type == NodeType::AND)
    {
        std::vector<int> leftRows;
        std::vector<int> rightRows;

        bool left =
            FindRowsDFS(
                node->left,
                attributes,
                leftRows);

        bool right =
            FindRowsDFS(
                node->right,
                attributes,
                rightRows);

        if(left && right)
        {
            rows.insert(
                rows.end(),
                leftRows.begin(),
                leftRows.end());

            rows.insert(
                rows.end(),
                rightRows.begin(),
                rightRows.end());

            return true;
        }

        return false;
    }

    /*
        OR
    */

    if(node->type == NodeType::OR)
    {
        std::vector<int> leftRows;

        if(FindRowsDFS(
                node->left,
                attributes,
                leftRows))
        {
            rows.insert(
                rows.end(),
                leftRows.begin(),
                leftRows.end());

            return true;
        }

        std::vector<int> rightRows;

        if(FindRowsDFS(
                node->right,
                attributes,
                rightRows))
        {
            rows.insert(
                rows.end(),
                rightRows.begin(),
                rightRows.end());

            return true;
        }

        return false;
    }

    return false;
}

}

/*-------------------------------------------------------------*/

bool FindMinimalSatisfiedRows(
        const std::shared_ptr<AccessNode>& root,
        const std::vector<std::string>& attributes,
        std::vector<int>& rows)
{
    rows.clear();

    bool ok =
        FindRowsDFS(
            root,
            attributes,
            rows);

    if(!ok)
        return false;

    std::sort(
        rows.begin(),
        rows.end());

    rows.erase(
        std::unique(
            rows.begin(),
            rows.end()),
        rows.end());

    return true;
}

/*==============================================================
    Print Tree
==============================================================*/

namespace
{

void PrintTreeDFS(
        const std::shared_ptr<AccessNode>& node,
        int depth)
{
    if(node == nullptr)
        return;

    for(int i = 0; i < depth; ++i)
    {
        std::cout << "    ";
    }

    if(node->IsLeaf())
    {
        std::cout
            << node->attribute
            << " ["
            << node->row
            << "]"
            << std::endl;

        return;
    }

    if(node->type == NodeType::AND)
        std::cout << "AND" << std::endl;
    else
        std::cout << "OR" << std::endl;

    PrintTreeDFS(
        node->left,
        depth + 1);

    PrintTreeDFS(
        node->right,
        depth + 1);
}

}

/*-------------------------------------------------------------*/

void PrintTree(
        const std::shared_ptr<AccessNode>& root,
        int depth)
{
    PrintTreeDFS(
        root,
        depth);
}

/*==============================================================
    Matrix Information
==============================================================*/

void PrintLSSMatrix(
        const LSSMatrix& matrix)
{
    std::cout
        << "\nLSS Matrix"
        << std::endl;

    for(size_t i = 0; i < matrix.matrix.size(); ++i)
    {
        std::cout
            << matrix.rho[i]
            << " : ";

        for(size_t j = 0;
            j < matrix.matrix[i].size();
            ++j)
        {
            char* s =
                BN_bn2dec(
                    matrix.matrix[i][j]);

            std::cout
                << s
                << " ";

            OPENSSL_free(s);
        }

        std::cout
            << std::endl;
    }
}