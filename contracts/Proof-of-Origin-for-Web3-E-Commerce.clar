(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-not-authorized (err u103))

(define-non-fungible-token product uint)

(define-map product-details
    uint 
    {
        manufacturer: principal,
        name: (string-ascii 50),
        serial: (string-ascii 64),
        timestamp: uint,
        verified: bool
    }
)

(define-map manufacturer-registry
    principal 
    {
        name: (string-ascii 50),
        verified: bool,
        products-registered: uint
    }
)

(define-map product-history
    uint
    (list 10 {
        action: (string-ascii 20),
        timestamp: uint,
        actor: principal
    })
)

(define-data-var product-counter uint u0)

(define-public (register-manufacturer (name (string-ascii 50)))
    (let
        ((manufacturer tx-sender))
        (asserts! (is-none (map-get? manufacturer-registry manufacturer)) err-already-exists)
        (ok (map-set manufacturer-registry 
            manufacturer
            {
                name: name,
                verified: false,
                products-registered: u0
            }
        ))
    )
)

(define-public (verify-manufacturer (manufacturer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (is-some (map-get? manufacturer-registry manufacturer)) err-not-found)
        (ok (map-set manufacturer-registry
            manufacturer
            (merge (unwrap-panic (map-get? manufacturer-registry manufacturer))
                { verified: true })))
    )
)

(define-public (register-product (name (string-ascii 50)) (serial (string-ascii 64)))
    (let
        ((manufacturer tx-sender)
         (product-id (+ (var-get product-counter) u1))
         (manufacturer-data (unwrap! (map-get? manufacturer-registry manufacturer) err-not-found)))
        
        (asserts! (get verified manufacturer-data) err-not-authorized)
        
        (try! (nft-mint? product product-id manufacturer))
        
        (map-set product-details product-id
            {
                manufacturer: manufacturer,
                name: name,
                serial: serial,
                timestamp: burn-block-height,
                verified: true
            }
        )
        
        (map-set manufacturer-registry
            manufacturer
            (merge manufacturer-data 
                { products-registered: (+ (get products-registered manufacturer-data) u1) }))
        
        (map-set product-history product-id
            (list 
                {
                    action: "registered",
                    timestamp: burn-block-height,
                    actor: manufacturer
                }
            ))
        
        (var-set product-counter product-id)
        (ok product-id)
    )
)

(define-read-only (get-product-details (product-id uint))
    (map-get? product-details product-id)
)

(define-read-only (get-product-history (product-id uint))
    (map-get? product-history product-id)
)

(define-read-only (get-manufacturer-details (manufacturer principal))
    (map-get? manufacturer-registry manufacturer)
)

(define-public (transfer-product (product-id uint) (recipient principal))
    (let
        ((sender tx-sender)
         (history (unwrap! (map-get? product-history product-id) err-not-found)))
        
        (asserts! (is-owner product-id sender) err-not-authorized)
        (try! (nft-transfer? product product-id sender recipient))
        
        (map-set product-history product-id
            (unwrap-panic (as-max-len? 
                (append history
                    {
                        action: "transferred",
                        timestamp: burn-block-height,
                        actor: sender
                    }
                ) u10)))
        (ok true)
    )
)

(define-private (is-owner (product-id uint) (user principal))
    (is-eq user (unwrap! (nft-get-owner? product product-id) false))
)