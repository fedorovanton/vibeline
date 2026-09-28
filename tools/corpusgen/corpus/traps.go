package corpus

// Ловушки: фрагменты, похожие на персональные данные, которыми они не являются.
// Размечаются в поле traps, а не spans: маскировать их не надо, по ним считается
// число ложных срабатываний (ТЗ §3.2.1, AC-202).
//
// Часть шаблонов смешанная: в одном запросе есть и настоящие ПД, и ловушка.
// Это важнее «чистых» ловушек — детектор обязан различать их в одном контексте,
// а не только в изолированных предложениях.

// trapTmpl — шаблон записи с ловушкой. Поле reason задаёт вид ловушки и
// используется для равномерного перебора всех видов.
type trapTmpl struct {
	reason string
	make   func(g *gen) []piece
}

var trapTemplates []trapTmpl

// namesakes — однофамильцы публичных персон. Это уже настоящие ПД: фамилия
// известного человека у обычного клиента не отменяет защиту (AC-203).
var namesakes []func(g *gen) []piece

func init() {
	trapTemplates = []trapTmpl{
		{ReasonPublicFigure, func(g *gen) []piece {
			f := pick(g.r, publicFigures)
			return join(
				lit("Расскажи, в каком году "), lit(f.role+" "),
				trapVal(KFullName, ReasonPublicFigure, f.nom),
				lit(" закончил самое известное произведение, нужна цитата для рассылки."),
			)
		}},
		{ReasonPublicFigure, func(g *gen) []piece {
			f := pick(g.r, publicFigures)
			return join(
				lit("Клиент спрашивает, есть ли карта с портретом, на котором "), lit(f.role+" "),
				trapVal(KFullName, ReasonPublicFigure, f.nom),
				lit(" — уточни в каталоге дизайнов."),
			)
		}},
		{ReasonPublicFigure, func(g *gen) []piece {
			f := pick(g.r, publicFigures)
			return join(
				lit("Подбери материалы про "),
				trapVal(KFullName, ReasonPublicFigure, f.gen),
				lit(" для школьной программы финансовой грамотности."),
			)
		}},
		{ReasonToponym, func(g *gen) []piece {
			t := pick(g.r, toponymStreets)
			return join(
				lit("Ближайшее отделение — на "), lit(t.kind+" "),
				trapVal(KFullName, ReasonToponym, t.name),
				lit(", уточни часы работы в субботу."),
			)
		}},
		{ReasonToponym, func(g *gen) []piece {
			t := pick(g.r, toponymStreets)
			return join(
				lit("Банкомат на "), lit(t.kind+" "),
				trapVal(KFullName, ReasonToponym, t.name),
				lit(" не выдаёт наличные, оформи заявку в службу инкассации."),
			)
		}},
		{ReasonOrgAddress, func(g *gen) []piece {
			return join(
				lit("Отделение банка находится по адресу "),
				trapVal(KAddress, ReasonOrgAddress, g.orgAddress()),
				lit(" — подскажи, как туда доехать от вокзала."),
			)
		}},
		{ReasonOrgAddress, func(g *gen) []piece {
			return join(
				lit("В выписке указан адрес офиса банка "),
				trapVal(KAddress, ReasonOrgAddress, g.orgAddress()),
				lit(", это адрес организации, а не клиента."),
			)
		}},
		{ReasonHotline, func(g *gen) []piece {
			return join(
				lit("Телефон горячей линии "),
				trapVal(KPhone, ReasonHotline, g.hotline()),
				lit(" напечатан на обороте карты — это действующий номер?"),
			)
		}},
		{ReasonHotline, func(g *gen) []piece {
			return join(
				lit("Переадресуй обращение на линию поддержки "),
				trapVal(KPhone, ReasonHotline, g.hotline()),
				lit(", там разберутся быстрее."),
			)
		}},
		{ReasonContractNumber, func(g *gen) []piece {
			return join(
				lit("Номер договора "),
				trapVal(KPassportNumber, ReasonContractNumber, g.contractNumber()),
				lit(" — найди по нему условия обслуживания."),
			)
		}},
		{ReasonContractNumber, func(g *gen) []piece {
			return join(
				lit("В реестре договор "),
				trapVal(KPassportNumber, ReasonContractNumber, g.contractNumber()),
				lit(" закрыт, проверь дату закрытия и остаток."),
			)
		}},
		{ReasonEventDate, func(g *gen) []piece {
			return join(
				lit("Встреча с персональным менеджером назначена на "),
				trapVal(KBirthDate, ReasonEventDate, renderDate(g.recentDate(2026, 2), 0, cNom)),
				lit(", напомни клиенту за час."),
			)
		}},
		{ReasonEventDate, func(g *gen) []piece {
			return join(
				lit("Очередной платёж по графику "),
				trapVal(KBirthDate, ReasonEventDate, renderDate(g.recentDate(2026, 2), 6, cNom)),
				lit(" — проверь, хватит ли остатка на счёте."),
			)
		}},

		// Смешанные записи: настоящие ПД и ловушка в одном предложении.
		{ReasonOrgAddress, func(g *gen) []piece {
			p := g.person()
			return join(
				lit(litClient), val(KFullName, g.fullName(p, cNom)),
				lit(" спрашивает, работает ли отделение по адресу "),
				trapVal(KAddress, ReasonOrgAddress, g.orgAddress()),
				lit(" в воскресенье."),
			)
		}},
		{ReasonHotline, func(g *gen) []piece {
			return join(
				lit("Клиент с номера "), val(KPhone, g.phone()),
				lit(" жалуется, что по линии поддержки "),
				trapVal(KPhone, ReasonHotline, g.hotline()),
				lit(" его не соединяют с оператором."),
			)
		}},
		{ReasonToponym, func(g *gen) []piece {
			t := pick(g.r, toponymStreets)
			return join(
				lit("Доставь карту "), val(KCardNumber, g.cardNumber()),
				lit(" по адресу "), val(KAddress, g.address()),
				lit(": отделение на "), lit(t.kind+" "),
				trapVal(KFullName, ReasonToponym, t.name),
				lit(" уже закрыто."),
			)
		}},
		{ReasonContractNumber, func(g *gen) []piece {
			p := g.person()
			return join(
				lit(litFindClient), val(KFullName, g.fullName(p, cAcc)),
				lit(litPassport), g.passport(),
				lit("; номер договора "),
				trapVal(KPassportNumber, ReasonContractNumber, g.contractNumber()),
				lit(" указан в обращении."),
			)
		}},
		{ReasonEventDate, func(g *gen) []piece {
			p := g.person()
			return join(
				lit(litClient), val(KFullName, g.fullName(p, cNom)),
				lit(" "+p.verb("родился", "родилась")+" "), g.datePieces(KBirthDate, g.birthDate(), cGen),
				lit(", а встреча назначена на "),
				trapVal(KBirthDate, ReasonEventDate, renderDate(g.recentDate(2026, 2), 0, cNom)),
				lit(" — не перепутай даты."),
			)
		}},
		{ReasonPublicFigure, func(g *gen) []piece {
			p := g.person()
			f := pick(g.r, publicFigures)
			return join(
				lit(litClient), val(KFullName, g.fullName(p, cNom)),
				lit(" просит открытку, где изображён "), lit(f.role+" "),
				trapVal(KFullName, ReasonPublicFigure, f.nom),
				lit("; доставка на "), val(KAddress, g.address()), lit("."),
			)
		}},
	}

	namesakes = []func(g *gen) []piece{
		func(g *gen) []piece {
			p := g.namesake()
			return join(
				lit(litClient), val(KFullName, g.fullName(p, cNom)),
				lit(" просит выписку по счёту, паспорт "), g.passport(), lit("."),
			)
		},
		func(g *gen) []piece {
			p := g.namesake()
			return join(
				lit("Оформи перевод на "), val(KFullName, g.fullName(p, cAcc)),
				lit(", карта получателя "), val(KCardNumber, g.cardNumber()), lit("."),
			)
		},
		func(g *gen) []piece {
			p := g.namesake()
			return join(
				lit("В заявке заявитель "), val(KFullName, g.fullName(p, cNom)),
				lit(", телефон "), val(KPhone, g.phone()),
				lit(" — это наш клиент, а не однофамилец из новостей."),
			)
		},
	}
}
