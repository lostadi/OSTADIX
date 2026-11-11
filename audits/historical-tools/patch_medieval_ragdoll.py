import re

with open('/Users/ustad/.config/ostadix/term/medieval.O', 'r') as f:
    content = f.read()

# Using regex to replace the class from class VerletRagdoll: down to the end of step
pattern = re.compile(r'class VerletRagdoll:.*?p2\[\'y\'\] -= dy \* 0\.5 \* diff', re.DOTALL)

new_ragdoll = '''class VerletRagdoll:
    # 9-point articulated ragdoll with mass-weighted constraints for realistic medieval combat collapse
    # Points: head, neck, r_shoulder, l_shoulder, torso/hips, r_knee, l_knee, r_foot, l_foot
    JOINT_MASS = [5.0, 3.5, 9.0, 9.0, 32.0, 8.0, 8.0, 4.0, 4.0]  # armored knight masses
    CONSTRAINT_PAIRS = [(0,1,3.5), (1,2,3.5), (1,3,3.5), (1,4,7.5),
                        (4,5,5.5), (4,6,5.5), (5,7,5.0), (6,8,5.0),
                        (2,4,6.5), (3,4,6.5)]  # spine brace for torso rigidity

    def __init__(self, x_base, y_base, facing=1):
        f = facing
        self.points = [
            {'x': float(x_base),       'y': float(y_base - 14), 'ox': float(x_base),       'oy': float(y_base - 14), 'm': 5.0},   # 0 head
            {'x': float(x_base),       'y': float(y_base - 11), 'ox': float(x_base),       'oy': float(y_base - 11), 'm': 3.5},   # 1 neck
            {'x': float(x_base + f*3), 'y': float(y_base - 10), 'ox': float(x_base + f*3), 'oy': float(y_base - 10), 'm': 9.0},   # 2 r_shoulder
            {'x': float(x_base - f*3), 'y': float(y_base - 10), 'ox': float(x_base - f*3), 'oy': float(y_base - 10), 'm': 9.0},   # 3 l_shoulder
            {'x': float(x_base),       'y': float(y_base - 4),  'ox': float(x_base),       'oy': float(y_base - 4),  'm': 32.0},  # 4 hips/torso
            {'x': float(x_base + f*2), 'y': float(y_base - 1),  'ox': float(x_base + f*2), 'oy': float(y_base - 1),  'm': 8.0},   # 5 r_knee
            {'x': float(x_base - f*2), 'y': float(y_base - 1),  'ox': float(x_base - f*2), 'oy': float(y_base - 1),  'm': 8.0},   # 6 l_knee
            {'x': float(x_base + f*2), 'y': float(y_base),      'ox': float(x_base + f*2), 'oy': float(y_base),      'm': 4.0},   # 7 r_foot
            {'x': float(x_base - f*2), 'y': float(y_base),      'ox': float(x_base - f*2), 'oy': float(y_base),      'm': 4.0},   # 8 l_foot
        ]
        self.facing = facing
        self.settled = False
        self.impact_frame = 0
        self.blood_drip_sites = []     # accumulates floor-impact blood positions
        self.gore_trail = []           # positions where entrails/blood dragged

    def apply_impulse(self, ix, iy):
        # Head whiplash — weapon momentum transfers most violently to the skull
        self.points[0]['ox'] -= ix * 2.6
        self.points[0]['oy'] -= iy * 2.0
        # Neck follows
        self.points[1]['ox'] -= ix * 1.8
        self.points[1]['oy'] -= iy * 1.2
        # Shoulders splay outward from impact
        self.points[2]['ox'] -= ix * 1.2
        self.points[3]['ox'] -= ix * 0.5
        # Heavy armored torso resists more
        self.points[4]['ox'] -= ix * 0.3
        # Legs barely move initially
        self.points[5]['ox'] -= ix * 0.1
        self.points[6]['ox'] -= ix * 0.1

    def total_kinetic_energy(self):
        ke = 0.0
        for p in self.points:
            vx = p['x'] - p['ox']
            vy = p['y'] - p['oy']
            ke += 0.5 * p['m'] * (vx*vx + vy*vy)
        return ke

    def step(self, floor_y=24.0, gravity=0.46, friction=0.76):
        if self.settled:
            return
        self.impact_frame += 1
        any_moving = False
        for p in self.points:
            inv_m = 1.0 / p['m']
            damping = 0.93 + 0.03 * min(1.0, p['m'] / 32.0)  # armored mass damps more
            vx = (p['x'] - p['ox']) * damping
            vy = (p['y'] - p['oy']) * damping + gravity * (1.0 + inv_m * 0.08)
            p['ox'] = p['x']
            p['oy'] = p['y']
            p['x'] += vx
            p['y'] += vy
            if p['y'] >= floor_y:
                impact_vel = abs(vy)
                p['y'] = floor_y
                restitution = 0.15 + 0.06 * inv_m  # armor makes bounces heavier/deader
                p['oy'] = floor_y + (p['y'] - p['oy']) * restitution
                p['ox'] = p['x'] - (p['x'] - p['ox']) * friction
                if impact_vel > 1.0:
                    self.blood_drip_sites.append((p['x'], floor_y, impact_vel))
                    self.gore_trail.append((p['x'], floor_y))
            if abs(p['x'] - p['ox']) > 0.04 or abs(p['y'] - p['oy']) > 0.04:
                any_moving = True

        # 6 constraint iterations for stable armored collapse
        for _ in range(6):
            for i1, i2, rest_len in self.CONSTRAINT_PAIRS:
                p1 = self.points[i1]
                p2 = self.points[i2]
                dx = p2['x'] - p1['x']
                dy = p2['y'] - p1['y']
                dist = math.hypot(dx, dy) or 0.001
                diff = (dist - rest_len) / dist
                total_m = p1['m'] + p2['m']
                w1 = p2['m'] / total_m
                w2 = p1['m'] / total_m
                p1['x'] += dx * w1 * diff
                p1['y'] += dy * w1 * diff
                p2['x'] -= dx * w2 * diff
                p2['y'] -= dy * w2 * diff

        if self.impact_frame > 35 and not any_moving:
            self.settled = True
            
        # Clean up any old code block artifacts below if needed
        # (Since we matched up to the exact end, we replace exactly that)
        # But wait, we matched up to "p2['y'] -= dy * 0.5 * diff", which is the end of the step loop.
        # So we just append this:
        # Actually I just put settled = True here.'''

content, count = pattern.subn(new_ragdoll, content, 1)

if count > 0:
    with open('/Users/ustad/.config/ostadix/term/medieval.O', 'w') as f:
        f.write(content)
    print("Medieval.O VerletRagdoll patched successfully")
else:
    print("Patch failed! Could not match the VerletRagdoll class.")
