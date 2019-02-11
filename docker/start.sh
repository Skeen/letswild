#!/bin/bash
#
# Gunicorn shell command for starting letswild.
#
# Written by Emil Madsen.
set -e

# Print help text
show_help()
{
   echo "Usage: start.sh [OPTIONS]" 
   echo "" 
   echo "Examples:" 
   echo "  start.sh -w 5 -t 4 # Run 5 workers, 4 threads each" 
   echo "" 
   echo " Options:" 
   echo "" 
   echo "  -w  Workers, number of worker processes."
   echo "      Defaults to 1."
   echo "  -t  Threads, number of threads per worker processes."
   echo "      Defaults to 1."
   echo "" 
   echo " Other options:" 
   echo "  -?  This help message" 
   echo "  -h  This help message" 
   echo "" 
   echo "Report bugs to <emil@magenta.dk>." 
}

# How many seconds before file is deemed out of date
WORKERS=1
THREADS=1

# Parse commandline options
while getopts "h?w:t:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 3
        ;;
    w)  WORKERS=$OPTARG
        ;;
    t)  THREADS=$OPTARG
        ;;
    esac
done
shift $((OPTIND-1))

echo "Starting Gunicorn."
exec gunicorn letswild:app \
    --bind [::]:8000 \
    --workers=$WORKERS \
    --threads=$THREADS \
    --timeout=120 \
    --graceful-timeout=120

