<?php
namespace App\Config;

class TIPConfig
{
    const YARAIFY_API_URL     = 'https://yaraify-api.abuse.ch/api/v1/';
    const ABUSE_IP_URL        = 'https://api.abuseipdb.com/api/v2/check/';
    const MALPROBE_URL        = 'https://malprob.io/api/search/';
    const MALWARE_BAZAAR_URL  = 'https://mb-api.abuse.ch/api/v1/';
    const VIRUSTOTAL_URL      = 'https://www.virustotal.com/api/v3/';
    const CROWDSEC_URL        = 'https://cti.api.crowdsec.net/v2/smoke/';
    const CRIMINAL_IP_URL     = 'https://api.criminalip.io/v1/asset/ip/report/summary';
    const THREATBOOK_URL      = 'https://api.threatbook.io/v1/community/ip';
    const IPAPI_URL           = 'http://ip-api.com/json/';

    public static function getHashSources(): array
    {
        return [
            'virustotal' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::VIRUSTOTAL_URL . "files/{$obs}",
                'headers' => [
                    'User-Agent' => 'Argus Aggregator/1.0',
                    'x-apikey'   => $_ENV['VT_API_KEY'] ?? ''
                ]
            ],
            'malwarebazaar' => [
                'method'  => 'POST',
                'url'     => self::MALWARE_BAZAAR_URL,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Auth-Key'     => $_ENV['ABUSECH_API_KEY'] ?? ''
                ],
                'body'     => fn($obs) => http_build_query(['query' => 'get_info', 'hash' => $obs])
            ],
            'yaraify' => [
                'method'  => 'POST',
                'url'     => self::YARAIFY_API_URL,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Auth-Key'     => $_ENV['ABUSECH_API_KEY'] ?? ''
                ],
                'body'     => fn($obs) => json_encode(['query' => 'lookup_hash', 'search_term' => $obs])
            ],
            'malprobe' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::MALPROBE_URL . $obs,
                'headers' => [
                    'Authorization' => 'Token ' . ($_ENV['MALPROBE_API_KEY'] ?? '')
                ]
            ],
            'opencti' => [
                'method' => 'POST',
                'url' => $_ENV['OPENCTI_URL'] . '/graphql',
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . ($_ENV['OPENCTI_API_KEY'] ?? '')
                ],
                'body' => fn($obs) => json_encode([
                    'query' => file_get_contents(ROOTPATH . '/script/query.graphql'),
                    'variables' => [
                        'count' => 1,
                        'search' => $obs,
                        'orderMode' => 'desc',
                        'orderBy' => '_score',
                        'filters' => [
                            'mode' => 'and',
                            'filters' => [
                                [
                                    'key' => 'entity_type',
                                    'values' => [],
                                    'operator' => 'eq',
                                    'mode' => 'or'
                                ]
                            ],
                            'filterGroups' => []
                        ]
                    ],
                    'operationName' => 'StixCyberObservablesLinesPaginationQuery'
                ])
            ]
        ];
    }

    public static function getIpSources(): array
    {
        $sources = [
            'virustotal' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::VIRUSTOTAL_URL . "ip_addresses/{$obs}",
                'headers' => [
                    'User-Agent' => 'Argus Aggregator/1.0',
                    'x-apikey'   => $_ENV['VT_API_KEY'] ?? ''
                ]
            ],
            'threatbook' => [
                'method'  => 'POST',
                'url'     => self::THREATBOOK_URL,
                'headers' => [
                    'Accept' => 'application/json'
                ],
                'multipart' => fn($obs) => [
                    [
                    'name'     => 'resource',
                    'contents' => $obs
                    ],
                    [
                    'name'     => 'apikey',
                    'contents' => $_ENV['THREATBOOK_API_KEY'] ?? ''
                    ],
                    [
                    'name'     => 'include',
                    'contents' => 'judgements'
                    ]
                ]
            ],
            'abuseipdb' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::ABUSE_IP_URL . '?' . http_build_query([
                    'ipAddress'    => $obs,
                    'maxAgeInDays' => 90,
                    'verbose'      => true
                ]),
                'headers' => [
                    'Key'    => $_ENV['ABUSEIP_API_KEY'] ?? '',
                    'Accept' => 'application/json'
                ]
            ],
            'crowdsec' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::CROWDSEC_URL . $obs,
                'headers' => [
                    'x-api-key'    => $_ENV['CROWDSEC_API_KEY'] ?? '',
                    'Accept' => 'application/json'
                ]
            ],
            'criminalip' => [
                'method'  => 'GET',
                'url'     => fn($obs) => self::CRIMINAL_IP_URL . "?ip={$obs}",
                'headers' => [
                    'x-api-key'    => $_ENV['CRIMINALIP_API_KEY'] ?? '',
                    'Accept' => 'application/json'
                ]
            ],
            'ipapi' => [
                'method' => 'GET',
                'url' => fn($obs) => self::IPAPI_URL . "{$obs}?country,isp,org,as,city,countryCode"
            ]
        ];

        if (!empty($_ENV['OPENCTI_URL']) && !empty($_ENV['OPENCTI_API_KEY'])) {
            $sources['opencti'] = [
                'method' => 'POST',
                'url' => $_ENV['OPENCTI_URL'] . '/graphql',
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $_ENV['OPENCTI_API_KEY']
                ],
                'body' => fn($obs) => json_encode([
                    'query' => file_get_contents(ROOTPATH . '/script/query.graphql'),
                    'variables' => [
                    'count' => 1,
                    'search' => $obs,
                    'orderMode' => 'desc',
                    'orderBy' => '_score',
                    'filters' => [
                        'mode' => 'and',
                        'filters' => [
                        [
                            'key' => 'entity_type',
                            'values' => [],
                            'operator' => 'eq',
                            'mode' => 'or'
                        ]
                        ],
                        'filterGroups' => []
                    ]
                    ],
                    'operationName' => 'StixCyberObservablesLinesPaginationQuery'
                ])
            ];
        }

        return $sources;
    }

    public static function getSources(string $type): array
    {
        return $type === 'hash' ? self::getHashSources() : self::getIpSources();
    }
}
