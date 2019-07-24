#pragma once
#include "node.h"
#include <list>
#include <functional>

namespace taint
{
class NodeSequence
{
private:
  size_t stringLength = 0;
  std::list<TaintNode> sequence;
  void shift(size_t offset);
  void cut(size_t pos);

public:
  static const size_t npos = static_cast<size_t>(-1);

  NodeSequence() = default;
  NodeSequence(const NodeSequence &src) = default;
  NodeSequence(size_t stringLength, std::string varsSource = "", std::string keyName = "", bool tainted = false);

  size_t taintedSize() const;
  size_t length() const;
  std::list<TaintNode> getSequence() const;

  NodeSequence &insert(size_t pos, const NodeSequence &inns);
  NodeSequence &insert(size_t pos, size_t lengthUntainted);
  NodeSequence &append(const NodeSequence &inns);
  NodeSequence &append(size_t lengthUntainted);
  NodeSequence &erase(size_t pos, size_t len = npos);
  NodeSequence sub(size_t pos, size_t len = npos);
  void read(std::function<void(const TaintNode &node)> handler) const;
  std::string dump() const;
};
} // namespace taint
