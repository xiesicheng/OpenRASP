#pragma once
#include "node_sequence.h"
#include <set>

namespace taint
{
class SequenceManager
{
private:
  std::set<NodeSequence *> sequences;

public:
  SequenceManager() = default;
  SequenceManager(const SequenceManager &src) = delete;
  virtual ~SequenceManager();
  virtual void registerSequence(NodeSequence *nodeSequence);
  virtual bool existSequence(NodeSequence *nodeSequence);
  virtual void clear();
};
} // namespace taint
