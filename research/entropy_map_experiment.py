import os
import math
import numpy as np

class UniversalEntropyMapEngine:
    def __init__(self, block_size=256, grid_width=32):
        self.block_size = block_size
        self.grid_width = grid_width

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """حساب إنتروبيا شانون للكتلة البايتية بدقة."""
        if not data:
            return 0.0
        length = len(data) # to intro
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy # القيمة تكون بين 0.0 و 8.0

    def generate_entropy_map(self, file_path: str) -> np.ndarray:
        """
        قراءة أي ملف في العالم، تحويله إلى تدفق، وحساب خريطة الإنتروبيا الخاصة به
        على شكل مصفوفة شبكية جاهزة للذكاء الاصطناعي.
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            raise IOError(f"فشل في قراءة الملف: {e}")

        file_len = len(content)
        if file_len == 0:
            return np.zeros((1, self.grid_width), dtype=float)

        entropy_values = []
        
        # المرور على الملف كتل متتالية واستخراج إنتروبيا كل كتلة
        for i in range(0, file_len, self.block_size):
            block = content[i:i + self.block_size]
            ent = self._calculate_shannon_entropy(block)
            # تطبيع القيمة لتصبح بين 0.0 و 1.0 لتسهيل تدريب الذكاء الاصطناعي
            entropy_values.append(ent / 8.0)

        if not entropy_values:
            entropy_values = [0.0]

        # إعادة تشكيل قائمة القيم لتصبح مصفوفة شبكية (Grid / Matrix) ذات أبعاد ثابتة
        arr = np.array(entropy_values, dtype=float)
        
        # ضبط الأبعاد لتتوافق مع عرض الشبكة المحدد
        total_elements = len(arr)
        rows = math.ceil(total_elements / self.grid_width)
        padded_size = rows * self.grid_width
        
        # حشو المصفوفة بـ أصفار إذا لزم الأمر لتوحيد الأبعاد
        padded_arr = np.pad(arr, (0, padded_size - total_elements), 'constant')
        entropy_map = padded_arr.reshape((rows, self.grid_width))

        return entropy_map

# ==========================================
# اختبار الكود عملياً للتأكد من فاعليته الفورية
# ==========================================
if __name__ == "__main__":
    engine = UniversalEntropyMapEngine(block_size=256, grid_width=32)
    test_file_path = "universal_test_file.bin"
    
    # إنشاء ملف تجريبي وهمي (يحتوي على أجزاء عادية وأجزاء مشفرة محاكاة لفيروس)
    with open(test_file_path, "wb") as f:
        f.write(b"Normal Text Data " * 200 + b"\xFF\x00\xAA\x55" * 500)
        
    try:
        entropy_matrix = engine.generate_entropy_map(test_file_path)
        print("تم استخراج خريطة الإنتروبيا الكلية للملف بنجاح تام!")
        print(f"شكل مصفوفة خريطة الإنتروبيا (Entropy Map Shape): {entropy_matrix.shape}")
        print("عينة من مصفوفة الإنتروبيا (توضح تدرج الفوضى من 0 إلى 1):\n", entropy_matrix[:3, :5])
        print("\nهذه المصفوفة الناتجة صالحة لأي ملف في الوجود، ويمكن إدخالها مباشرة لنموذج التصنيف!")
    finally:
        if os.path.exists(test_file_path):
            os.remove(test_file_path)