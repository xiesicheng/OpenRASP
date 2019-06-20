
#include "sequence_manager.h"

namespace taint
{

SequenceManager::~SequenceManager()
{
  clear();
}

void SequenceManager::registerSequence(NodeSequence *nodeSequence)
{
  printf("%s", nodeSequence->dump().c_str());
  sequences.push_back(nodeSequence);
}

void SequenceManager::clear()
{
  for (NodeSequence *sequence : sequences)
  {
    delete sequence;
  }
  sequences.clear();
}

} // namespace taint
