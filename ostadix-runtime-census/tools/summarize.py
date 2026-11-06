"""Print the census table from result JSON files: python3 -I summarize.py results/*.json"""
import json, sys
for p in sys.argv[1:]:
    r = json.load(open(p)); t = r["functions"]; m = r["instr"]; b = r["baseline_closed_ready"]
    needs = {k: v for k, v in r["census_functions"].items() if v}
    print(f"{r['name']}: {t} functions, {m} IR instructions, {r['extern_symbols']} undefined symbols ({r['libm_symbols']} libm)")
    print(f"  functions needing each missing feature: {needs}")
    print(f"  closed-ready with today's O-core feature set: {100*b['functions']/t:.1f}% of functions, {100*b['instr']/m:.1f}% of IR")
    steps, prev = [], b["instr"]
    for s in r["greedy_order"]:
        steps.append(f"{s['feature']} -> {100*s['closed_ready_instr']/m:.1f}%")
        if s["closed_ready_instr"] == m:
            break
    print("  greedy unlock (share of IR that is closed-ready after adding each feature): " + ", ".join(steps))
    print()
