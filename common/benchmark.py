"""Timing helpers shared by the benchmark utilities and GUIs."""

import time
from typing import Callable


def time_operation(operation: Callable[[], None], iterations: int) -> dict:
    """Run operation iterations times and summarise the elapsed times."""
    times = []
    for _ in range(iterations):
        start_time = time.time()
        operation()
        times.append(time.time() - start_time)

    return {
        'iterations': iterations,
        'average_time': sum(times) / len(times),
        'min_time': min(times),
        'max_time': max(times),
        'total_time': sum(times),
    }


def format_results(title: str, results: dict, precision: int = 4) -> str:
    """Render benchmark results as the multi-line text shown in the GUIs."""
    return (
        f"{title}\n"
        f"Iterations: {results['iterations']}\n"
        f"Average Time: {results['average_time']:.{precision}f}s\n"
        f"Min Time: {results['min_time']:.{precision}f}s\n"
        f"Max Time: {results['max_time']:.{precision}f}s\n"
        f"Total Time: {results['total_time']:.{precision}f}s\n"
    )
