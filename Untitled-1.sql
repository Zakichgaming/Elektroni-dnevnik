SELECT 
    student_id, 
    subject, 
    ROUND(AVG(CASE WHEN grade_type = 'control' THEN grade_value * 2 ELSE grade_value END), 2) AS weighted_avg
FROM grades
WHERE date BETWEEN '2023-09-01' AND '2023-12-31'
GROUP BY student_id, subject;