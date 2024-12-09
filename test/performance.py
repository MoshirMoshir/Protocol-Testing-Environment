from time import perf_counter
import sys

def measure_time(func, *args, **kwargs):
    """Measures the time taken by a function using high-precision timing."""
    start = perf_counter()
    result = func(*args, **kwargs)
    end = perf_counter()
    return result, end - start

def measure_average_time(func, iterations, *args, label="", **kwargs):
    """Measures the average time taken by a function over multiple iterations with progress updates."""
    total_time = 0
    for i in range(iterations):
        _, elapsed_time = measure_time(func, *args, **kwargs)
        total_time += elapsed_time

        # Update progress in the console with a label
        progress = f"{label} Progress: {i + 1}/{iterations} ({((i + 1) / iterations) * 100:.2f}%)"
        sys.stdout.write(f"\r{progress}")  # Overwrite the same line
        sys.stdout.flush()

    print()  # Move to a new line after progress is complete
    average_time = total_time / iterations
    return total_time, average_time
