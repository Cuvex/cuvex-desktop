"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

def clean_bytearray(input: bytearray):
    """Zeroizes the bytearray input
    """
    if not input:
        return
    for index in range(len(input)):
        input[index] = 0

def copy_and_clean(input) -> bytearray:
    """Copies the contents of input into a new bytearray and skips any zero byte.
    """
    if not input:
        return None

    total_count = len(input)
    result = bytearray(total_count - input.count(b'\x00'))
    result_index = 0
    for index in range(total_count):
        if input[index] != 0:
            result[result_index] = input[index]
            result_index += 1
    return result


def heap_permutation(words) -> list:
    """Genereates permutations with the elements of the input param using the
    Heap algorithm.
    """
    result = []

    def generate(size):
        if size == 1:
            result.append(words[:])
            return

        for i in range(size):
            generate(size - 1)

            if size % 2 == 1:
                words[0], words[size-1] = words[size-1], words[0]
            else:
                words[i], words[size-1] = words[size-1], words[i]

    generate(len(words))
    return result

def convert_str_to_code_points(input: str) -> list:
    """Converts every char in the input string to the corresponding Unicode code
    point.
    """
    result = []
    if not input:
        return result
    
    return [ord(char) for char in input]
