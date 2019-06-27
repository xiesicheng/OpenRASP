#include "node.h"

namespace taint
{

TaintNode::TaintNode(size_t startIndex, size_t endIndex, std::string varsSource, std::string keyName)
{
    this->startIndex = startIndex;
    this->endIndex = endIndex;
    this->varsSource = varsSource;
    this->keyName = keyName;
}

void TaintNode::shift(size_t offset)
{
    startIndex += offset;
    endIndex += offset;
}

void TaintNode::setStartIndex(size_t startIndex)
{
    this->startIndex = startIndex;
}

void TaintNode::setEndIndex(size_t endIndex)
{
    this->endIndex = endIndex;
}

size_t TaintNode::getStartIndex() const
{
    return startIndex;
}

size_t TaintNode::getEndIndex() const
{
    return endIndex;
}

std::string TaintNode::getSource() const
{
    return varsSource + "['" + keyName + "']";
}

std::string TaintNode::dump() const
{
    std::stringstream ss;
    ss << "( " << startIndex << " - " << endIndex << " )";
    ss << " source: " << getSource();
    return ss.str();
}

} // namespace taint
