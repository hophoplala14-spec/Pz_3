class InvalidSystemsCountError(ValueError):

    def __init__(self, count):
        super().__init__(f"Количество систем должно быть >= 1. Получено: {count}")

class InvalidHoursError(ValueError):

    def __init__(self, hours):
        super().__init__(f"Время с момента обнаружения не может быть отрицательным. Получено: {hours}")


class SecurityIncident:


    base_severity = 0

    def __init__(self, incident_id: str, affected_systems: int, hours_since_detected: float):
        self.incident_id = incident_id

        self.affected_systems = affected_systems
        self.hours_since_detected = hours_since_detected

    @property
    def affected_systems(self):
        return self._affected_systems

    @affected_systems.setter
    def affected_systems(self, value):
        # Проверка: количество систем >= 1
        if value < 1:
            raise InvalidSystemsCountError(value)
        self._affected_systems = value

    @property
    def hours_since_detected(self):
        return self._hours_since_detected

    @hours_since_detected.setter
    def hours_since_detected(self, value):

        if value < 0:
            raise InvalidHoursError(value)
        self._hours_since_detected = value

    def calculate_weight(self) -> float:

        raise NotImplementedError("Метод должен быть переопределен в наследниках")

    def get_criticality(self) -> str:

        weight = self.calculate_weight()
        if weight >= 50:
            return "CRITICAL"
        elif weight >= 20:
            return "HIGH"
        elif weight >= 5:
            return "MEDIUM"
        else:
            return "LOW"


class DDoSAttack(SecurityIncident):
    base_severity = 10
    def calculate_weight(self):
        time_factor = 1 + (self.hours_since_detected / 24)
        return self.base_severity * self.affected_systems * time_factor

class DataLeak(SecurityIncident):
    base_severity = 8
    def calculate_weight(self):
        time_factor = 1 + (self.hours_since_detected / 24)
        return self.base_severity * self.affected_systems * time_factor

class Phishing(SecurityIncident):
    base_severity = 3
    def calculate_weight(self):
        time_factor = 1 + (self.hours_since_detected / 24)
        return self.base_severity * self.affected_systems * time_factor


def __str__(self):
    return f"[{self.get_criticality()}] {self.__class__.__name__} (ID: {self.incident_id}) | Вес: {self.calculate_weight():.2f}"

def __repr__(self):
    return f"{self.__class__.__name__}(id='{self.incident_id}', systems={self.affected_systems}, hours={self.hours_since_detected})"

def __eq__(self, other):

    if not isinstance(other, SecurityIncident):
        return False
    return self.incident_id == other.incident_id

def __lt__(self, other):

    return self.calculate_weight() < other.calculate_weight()

def __add__(self, other):

    return self.calculate_weight() + other.calculate_weight()


SecurityIncident.__str__ = __str__
SecurityIncident.__repr__ = __repr__
SecurityIncident.__eq__ = __eq__
SecurityIncident.__lt__ = __lt__
SecurityIncident.__add__ = __add__


class IncidentQueue:


    def __init__(self):
        self._incidents = []

    def add_incident(self, incident: SecurityIncident):
        self._incidents.append(incident)

    def __len__(self):

        return len(self._incidents)

    def __getitem__(self, index):

        return self._incidents[index]


if __name__ == "__main__":
    print("=== 1. Создание объектов и добавление в контейнер ===")
    queue = IncidentQueue()

    ddos = DDoSAttack("INC-001", affected_systems=5, hours_since_detected=12)
    leak = DataLeak("INC-002", affected_systems=2, hours_since_detected=2)
    phish = Phishing("INC-003", affected_systems=1, hours_since_detected=1)

    queue.add_incident(ddos)
    queue.add_incident(leak)
    queue.add_incident(phish)

    print(f"Количество инцидентов в очереди (__len__): {len(queue)}")

    print("\n=== 2. Вывод на экран (демонстрация __str__) ===")
    for incident in queue:
        print(incident)

    print("\n=== 3. Сортировка контейнера (демонстрация __lt__) ===")

    sorted_incidents = sorted(queue._incidents)
    print("Инциденты после сортировки по весу (от меньшего к большему):")
    for incident in sorted_incidents:
        print(incident)

    print("\n=== 4. Вызов полиморфного метода в цикле ===")
    for incident in queue:
        print(f"Инцидент {incident.incident_id} ({incident.__class__.__name__}): "
              f"Вес = {incident.calculate_weight():.2f}, Критичность = {incident.get_criticality()}")

    print("\n=== 5.  __add__ ===")
    total_weight = queue[0] + queue[1]
    print(f"Суммарный вес инцидентов {queue[0].incident_id} и {queue[1].incident_id} = {total_weight:.2f}")

    print("\n=== 6. Вызов и перехват кастомного исключения ===")


    try:
        print("Пробуем создать инцидент с 0 затронутых систем...")
        bad_incident = DataLeak("INC-004", affected_systems=0, hours_since_detected=5)
    except InvalidSystemsCountError as e:
        print(f"Перехвачено исключение: {e}")

    try:
        print("\nПробуем создать инцидент с отрицательным временем...")
        bad_incident = Phishing("INC-005", affected_systems=1, hours_since_detected=-2)
    except InvalidHoursError as e:
        print(f"Перехвачено исключение: {e}")