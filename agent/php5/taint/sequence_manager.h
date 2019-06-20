#pragma once
#include "node_sequence.h"
#include <vector>

namespace taint
{
class SequenceManager
{
private:
  std::vector<NodeSequence *> sequences;

public:
  SequenceManager() = default;
  SequenceManager(const SequenceManager &src) = delete;
  virtual ~SequenceManager();
  void registerSequence(NodeSequence *nodeSequence);
  void clear();
};
} // namespace taint
