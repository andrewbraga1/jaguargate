package redteam

import (
	"strings"
	"testing"
)

func TestRunPounceSuiteAndLanguageSwitch(t *testing.T) {
	// 1. Default English ("en") report
	repEN := RunPounceSuite("en")
	if !repEN.AllPassed {
		t.Fatalf("expected all 8 Red-Team attack vectors to pass, got report:\n%s", repEN.FormatReport())
	}
	if len(repEN.Results) != 8 {
		t.Fatalf("expected 8 vectors, got %d", len(repEN.Results))
	}
	outEN := repEN.FormatReport()
	if !strings.Contains(outEN, "SECURITY AUDIT REPORT") || !strings.Contains(outEN, "VERDICT: PASSED") {
		t.Errorf("expected clean English report headers, got:\n%s", outEN)
	}

	// 2. Optional Portuguese ("pt-BR") report
	repPT := RunPounceSuite("pt-BR")
	outPT := repPT.FormatReport()
	if !strings.Contains(outPT, "RELATÓRIO DE AUDITORIA DE SEGURANÇA") || !strings.Contains(outPT, "VEREDITO: APROVADO") {
		t.Errorf("expected localized Portuguese report when lang='pt-BR', got:\n%s", outPT)
	}
}

func BenchmarkPounceFullSuite(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RunPounceSuite("en")
	}
}
