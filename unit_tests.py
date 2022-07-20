import conda

assert conda.check_constraint(
    (">=1.1,<2.0", "*_a"), {"version": "1.2.3", "build": "a_a"}
)
assert conda.check_constraint(
    (">=14.1,<15.0a0", None), {"version": "14.1", "build": "a_a"}
)
assert conda.check_constraint(
    ("==14.1", None), {"version": "14.1.2", "build": "a_a"}
)
