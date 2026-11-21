"""Tests de l'analyse des en-tetes (stdlib uniquement) : python3 -m unittest discover tests"""
import importlib.util
import pathlib
import unittest

_chemin = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "audit-headers.py"
_spec = importlib.util.spec_from_file_location("audit_headers", _chemin)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

HSTS = "strict-transport-security"


def etat_hsts(valeur):
    return audit.analyser_headers({HSTS: valeur})[HSTS]


class HstsMaxAge(unittest.TestCase):
    def test_valeur_valide(self):
        self.assertEqual(audit.hsts_max_age("max-age=31536000; includeSubDomains"), 31536000)

    def test_casse_espaces_guillemets(self):
        self.assertEqual(audit.hsts_max_age(' Max-Age = "31536000" '), 31536000)

    def test_valeurs_invalides(self):
        for v in ("max-age", "max-age=", "max-age=abc", "includeSubDomains", "max-age=-5"):
            self.assertIsNone(audit.hsts_max_age(v), v)


class AnalyseHsts(unittest.TestCase):
    def test_ok(self):
        r = etat_hsts("max-age=31536000")
        self.assertEqual((r["etat"], r["points"]), ("ok", 20))

    def test_ok_avec_guillemets(self):
        self.assertEqual(etat_hsts('max-age="31536000"')["etat"], "ok")

    def test_max_age_court(self):
        r = etat_hsts("max-age=3600")
        self.assertEqual((r["etat"], r["points"]), ("faible", 10))

    def test_en_tete_mal_forme_ne_plante_pas(self):
        for v in ("max-age", "max-age=", "max-age=abc"):
            self.assertEqual(etat_hsts(v)["etat"], "faible", v)

    def test_absent(self):
        self.assertEqual(audit.analyser_headers({})[HSTS]["etat"], "absent")


class Score(unittest.TestCase):
    def test_score_max_100(self):
        h = {
            "content-security-policy": "default-src 'self'",
            HSTS: "max-age=31536000",
            "x-frame-options": "deny",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        res = audit.analyser_headers(h)
        self.assertEqual(sum(r["points"] for r in res.values()), 100)
        self.assertEqual(len(audit.priorites(res)), 1)


if __name__ == "__main__":
    unittest.main()
