# Legacy Archive

Ten katalog nie należy do aktywnej ścieżki rozwoju.

Zawiera elementy starego eksperymentu, które:
- były pomocnicze,
- były tymczasowe,
- były częścią dawnych flow,
- albo nie pasują do nowej, kanonicznej architektury repo.

## Zasada

Nic z `legacy-archive/` nie może być traktowane jako:
- runtime core,
- source of truth,
- domyślna ścieżka działania,
- wymagany element automatu.

## Co tu trafia

Przykładowo:
- stare HTTP-first flow,
- stare direct sign/submit pathy,
- nieużywane tunele,
- stare prototypy,
- narzędzia ad hoc,
- rzeczy zachowane wyłącznie do porównania lub referencji.

## Jak używać

Tylko:
- do analizy historycznej,
- do odzyskiwania pomysłów,
- do ręcznego porównania starej i nowej wersji.

Nie wolno:
- importować stąd kodu bez świadomej decyzji,
- linkować tego jako dependency runtime,
- budować na tym nowego flow „na szybko”.

## Cel

Nowe repo ma mieć jedną architekturę.
Ten katalog istnieje tylko po to, żeby nie gubić historii, ale nie mieszać jej z aktywnym rdzeniem systemu.