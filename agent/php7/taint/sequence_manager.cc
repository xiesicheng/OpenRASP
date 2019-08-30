
#include "sequence_manager.h"

namespace taint
{

SequenceManager::~SequenceManager()
{
  clear();
}

void SequenceManager::registerSequence(NodeSequence *nodeSequence)
{
  sequences.insert(nodeSequence);
}

bool SequenceManager::existSequence(NodeSequence *nodeSequence)
{
  auto found = sequences.find(nodeSequence);
  return found != sequences.end();
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
