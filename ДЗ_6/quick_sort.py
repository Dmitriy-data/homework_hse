def quick_sort(a):
    a = list(a)
    if len(a) <= 1:
        return a

    pivot = a[len(a) // 2]
    left = [x for x in a if x < pivot]
    mid  = [x for x in a if x == pivot]
    right = [x for x in a if x > pivot]
    return quick_sort(left) + mid + quick_sort(right)