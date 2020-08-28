#include "processor.h"
#include "linux_parser.h"

// TODO: Return the aggregate CPU utilization
float Processor::Utilization() {
  float Total = LinuxParser::Jiffies();
  float Idle = LinuxParser::IdleJiffies();

  float CPU_usage = (Total - Idle) / Total;

  return CPU_usage;
}