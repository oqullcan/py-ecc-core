from __future__ import annotations

def modular_inverse(n: int, p: int) -> int:
    """Fermat'nın Küçük Teoremi ile modüler tersi hesaplar: n^(p-2) ≡ n⁻¹ (mod p)"""
    return pow(n, p - 2, p)

# @dataclass'ı kaldır
class Curve:
    """
    y^2 = x^3 + ax + b (mod p) formundaki bir eliptik eğriyi temsil eder.
    """
    def __init__(self, name: str, p: int, a: int, b: int, n: int, gx: int, gy: int):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.g = Point(self, gx, gy)

    def __str__(self):
        return f'Curve("{self.name}")'

    def __eq__(self, other):
        if not isinstance(other, Curve):
            return NotImplemented
        return (self.name, self.p, self.a, self.b, self.n, self.g) == (other.name, other.p, other.a, other.b, other.n, other.g)

class Point:
    """
    Bir eliptik eğri üzerindeki bir noktayı temsil eder.
    """
    def __init__(self, curve: Curve, x: int | None, y: int | None):
        self.curve = curve
        self.x = x
        self.y = y

        # Sonsuzdaki nokta kontrolü
        if self.x is None and self.y is None:
            return

        # Noktanın eğri üzerinde olduğunu doğrula
        if (self.y**2 - (self.x**3 + self.curve.a * self.x + self.curve.b)) % self.curve.p != 0:
            raise ValueError(f"Nokta ({self.x}, {self.y}) eğrinin üzerinde değil.")

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def is_at_infinity(self) -> bool:
        """Bu noktanın sonsuzdaki nokta olup olmadığını kontrol eder."""
        return self.x is None and self.y is None

    @property
    def is_identity(self):
        """Nokta, birim eleman (sonsuzdaki nokta) mı?"""
        return self.x is None and self.y is None

    def __add__(self, other: Point) -> Point:
        """İki noktayı toplar (eliptik eğri nokta toplamı)."""
        if self.curve != other.curve:
            raise TypeError("Aynı eğri üzerinde olmayan noktalar toplanamaz.")

        # Sonsuzdaki nokta ile toplama kuralları
        if self.is_at_infinity():
            return other
        if other.is_at_infinity():
            return self

        p_jac = _to_jacobian(self)
        q_jac = _to_jacobian(other)
        
        r_jac = _jacobian_add(p_jac, q_jac, self.curve)
        
        return _from_jacobian(r_jac, self.curve)


    def __mul__(self, k: int) -> Point:
        """
        Bir noktayı bir skaler ile çarpar (Jakoben koordinatları ile Double-and-Add).
        """
        if not isinstance(k, int):
            raise TypeError("Skaler bir tamsayı olmalıdır.")

        if self.is_at_infinity() or k % self.curve.n == 0:
            return Point(self.curve, None, None)

        if k < 0:
            return (-k) * (-self)

        result_jac = (1, 1, 0)  # Jakoben birim elemanı
        current_jac = _to_jacobian(self)

        while k > 0:
            if k & 1:
                result_jac = _jacobian_add(result_jac, current_jac, self.curve)
            current_jac = _jacobian_double(current_jac, self.curve)
            k >>= 1

        return _from_jacobian(result_jac, self.curve)

    def __rmul__(self, k: int) -> Point:
        """k * P için skaler çarpmayı etkinleştirir."""
        return self.__mul__(k)

    def __neg__(self) -> Point:
        """Bir noktanın negatifini döndürür: (x, -y)."""
        if self.is_at_infinity():
            return self
        return Point(self.curve, self.x, self.curve.p - self.y)

# --- Jakoben Koordinat Yardımcı Fonksiyonları ---

def _to_jacobian(p: Point):
    """Afin koordinatları Jakoben'e dönüştürür."""
    if p.is_at_infinity():
        return (1, 1, 0)
    return (p.x, p.y, 1)

def _from_jacobian(p, curve: Curve):
    """Jakoben koordinatları Afin'e dönüştürür."""
    x, y, z = p
    if z == 0:
        return Point(curve, None, None)
    
    z_inv = pow(z, -1, curve.p)
    z_inv_sq = (z_inv * z_inv) % curve.p
    
    x_aff = (x * z_inv_sq) % curve.p
    y_aff = (y * z_inv_sq * z_inv) % curve.p
    
    return Point(curve, x_aff, y_aff)

def _jacobian_double(p, curve: Curve):
    """Jakoben koordinatlarında bir noktayı ikiye katlar (point doubling)."""
    x, y, z = p
    if y == 0 or z == 0:
        return (1, 1, 0)

    y_sq = (y * y) % curve.p
    s = (4 * x * y_sq) % curve.p
    m = (3 * x * x + curve.a * pow(z, 4, curve.p)) % curve.p
    
    x_new = (m * m - 2 * s) % curve.p
    y_new = (m * (s - x_new) - 8 * y_sq * y_sq) % curve.p
    z_new = (2 * y * z) % curve.p
    
    return (x_new, y_new, z_new)

def _jacobian_add(p, q, curve: Curve):
    """Jakoben koordinatlarında iki noktayı toplar (point addition)."""
    x1, y1, z1 = p
    x2, y2, z2 = q

    if z1 == 0:
        return q
    if z2 == 0:
        return p

    z1_sq = (z1 * z1) % curve.p
    z2_sq = (z2 * z2) % curve.p
    
    u1 = (x1 * z2_sq) % curve.p
    u2 = (x2 * z1_sq) % curve.p
    
    s1 = (y1 * z2_sq * z2) % curve.p
    s2 = (y2 * z1_sq * z1) % curve.p
    
    h = (u2 - u1) % curve.p
    r = (s2 - s1) % curve.p
    
    if h == 0:
        if r == 0:
            return _jacobian_double(p, curve)
        else:
            return (1, 1, 0)
            
    h_sq = (h * h) % curve.p
    h_cu = (h * h_sq) % curve.p
    v = (u1 * h_sq) % curve.p
    
    x3 = (r * r - h_cu - 2 * v) % curve.p
    y3 = (r * (v - x3) - s1 * h_cu) % curve.p
    z3 = (z1 * z2 * h) % curve.p
    
    return (x3, y3, z3)
