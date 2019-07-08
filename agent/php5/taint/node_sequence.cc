
#include "node_sequence.h"

namespace taint
{

NodeSequence::NodeSequence(size_t stringLength, std::string varsSource, std::string keyName, bool tainted)
{
    this->stringLength = stringLength;
    if (tainted)
    {
        sequence.push_back({0, stringLength - 1, varsSource, keyName});
    }
}

std::list<TaintNode> NodeSequence::getSequence() const
{
    return sequence;
}

void NodeSequence::shift(size_t offset)
{
    for (TaintNode &node : sequence)
    {
        node.shift(offset);
    }
}

size_t NodeSequence::taintedSize() const
{
    return sequence.size();
}

size_t NodeSequence::length() const
{
    return stringLength;
}

void NodeSequence::cut(size_t pos)
{
    for (auto it = sequence.begin(); it != sequence.end(); it++)
    {
        if (pos > it->getStartIndex() &&
            pos <= it->getEndIndex())
        {
            TaintNode front(*it);
            front.setEndIndex(pos - 1);
            it->setStartIndex(pos);
            sequence.insert(it, front);
            break;
        }
    }
}

NodeSequence &NodeSequence::insert(size_t pos, const NodeSequence &inns)
{
    cut(pos);
    bool inserted = false;
    NodeSequence tmpns(inns);
    tmpns.shift(pos);
    std::list<TaintNode> tmpSequence = tmpns.getSequence();
    for (auto it = sequence.begin(); it != sequence.end(); it++)
    {
        if (it->getStartIndex() >= pos)
        {
            if (!inserted)
            {
                sequence.insert(it, tmpSequence.begin(), tmpSequence.end());
                inserted = true;
            }
            it->shift(inns.length());
        }
    }
    if (!inserted)
    {
        sequence.insert(sequence.end(), tmpSequence.begin(), tmpSequence.end());
        inserted = true;
    }
    stringLength += inns.length();
    return *this;
}

NodeSequence &NodeSequence::insert(size_t pos, size_t lengthUntainted)
{
    cut(pos);
    for (auto it = sequence.begin(); it != sequence.end(); it++)
    {
        if (it->getStartIndex() >= pos)
        {
            it->shift(lengthUntainted);
        }
    }
    stringLength += lengthUntainted;
    return *this;
}

NodeSequence &NodeSequence::append(const NodeSequence &inns)
{
    return insert(length(), inns);
}

NodeSequence &NodeSequence::append(size_t lengthUntainted)
{
    return insert(length(), lengthUntainted);
}

NodeSequence &NodeSequence::erase(size_t pos, size_t len)
{
    if (len == npos ||
        pos + len > stringLength)
    {
        len = stringLength - pos;
    }
    cut(pos);
    cut(pos + len);
    auto it = sequence.begin();
    while (it != sequence.end())
    {
        if (it->getEndIndex() < pos + len)
        {
            if (it->getStartIndex() >= pos)
            {
                it = sequence.erase(it);
                continue;
            }
        }
        else
        {
            it->shift(-len);
        }
        it++;
    }
    stringLength -= len;
}

NodeSequence NodeSequence::sub(size_t pos, size_t len)
{
    NodeSequence res(*this);
    if (len != npos && pos + len < stringLength)
    {
        res.erase(pos + len);
    }
    if (pos >= 0)
    {
        res.erase(0, pos);
    }
    return res;
}

NodeSequence NodeSequence::read(std::function<void(const TaintNode &node)> handler) const
{
    for (const TaintNode &taintNode : sequence)
    {
        if (handler)
        {
            handler(taintNode);
        }
    }
}

std::string NodeSequence::dump() const
{
    std::stringstream ss;
    ss << ">>>>>> START >>>>>>\n";
    for (auto it = sequence.begin(); it != sequence.end(); it++)
    {
        ss << it->dump() << "\n";
    }
    ss << "TOTAL LENGTH: " << stringLength << "\n";
    ss << "<<<<<<  END  <<<<<<\n";
    return ss.str();
}

} // namespace taint
