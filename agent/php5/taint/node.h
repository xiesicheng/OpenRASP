#pragma once
#include <cstdio>
#include <cstdint>
#include <string>
#include <sstream>

namespace taint
{
class TaintNode
{
private:
  size_t startIndex = 0l;
  size_t endIndex = 0l;
  std::string varsSource;
  std::string keyName;

public:
  TaintNode() = default;
  TaintNode(const TaintNode &src) = default;
  TaintNode(size_t startIndex, size_t endIndex, std::string varsSource, std::string keyName);
  void setStartIndex(size_t startIndex);
  void setEndIndex(size_t endIndex);
  size_t getStartIndex() const;
  size_t getEndIndex() const;
  void shift(size_t offset);
  std::string dump() const;
};
} // namespace taint
